/**
 * Java Voice Agent Starter - Backend Server
 *
 * Simple WebSocket bridge to Deepgram's Voice Agent API using Javalin, backed
 * by the official Deepgram Java SDK (`client.agent().v1().v1WebSocket()`).
 * Forwards messages (JSON and binary) bidirectionally between client and Deepgram.
 *
 * Key Features:
 * - WebSocket bridge to Deepgram Voice Agent API via the Deepgram Java SDK
 * - JWT session authentication via WebSocket subprotocol
 * - Project metadata from deepgram.toml
 * - Graceful shutdown with connection tracking
 *
 * Routes:
 *   GET  /api/session       - Issue signed session token
 *   GET  /api/metadata      - Project metadata from deepgram.toml
 *   WS   /api/voice-agent   - WebSocket bridge to Deepgram Agent API (auth required)
 *   GET  /health            - Health check
 */
package com.deepgram.starter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.deepgram.DeepgramClient;
import com.deepgram.core.ObjectMappers;
import com.deepgram.resources.agent.v1.websocket.V1WebSocketClient;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.toml.TomlMapper;
import io.github.cdimascio.dotenv.Dotenv;
import io.javalin.Javalin;
import io.javalin.websocket.WsConfig;
import io.javalin.websocket.WsContext;
import okio.ByteString;

import java.io.File;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

// ============================================================================
// CONFIGURATION
// ============================================================================

/**
 * Main application class for the Java Voice Agent Starter.
 * Manages HTTP routes, WebSocket bridge, and server lifecycle.
 */
public class App {

    /** Deepgram API key for authenticating upstream connections. */
    private static String deepgramApiKey;

    /** Shared Deepgram SDK client; the browser never sees the API key. */
    private static DeepgramClient deepgram;

    /** Server port, configurable via PORT environment variable. */
    private static int port;

    /** Server host, configurable via HOST environment variable. */
    private static String host;

    /** Secret key for signing JWT session tokens. */
    private static String sessionSecret;

    /** JWT expiry duration in seconds (1 hour). */
    private static final long JWT_EXPIRY_SECONDS = 3600;

    /** Reserved WebSocket close codes that cannot be set by applications (RFC 6455). */
    private static final Set<Integer> RESERVED_CLOSE_CODES = Set.of(1004, 1005, 1006, 1015);

    /** Tracks all active client WebSocket contexts for graceful shutdown. */
    private static final Set<WsContext> activeConnections = ConcurrentHashMap.newKeySet();

    /** Tracks Deepgram agent websocket clients keyed by client WsContext for cleanup. */
    private static final Map<WsContext, V1WebSocketClient> deepgramSessions = new ConcurrentHashMap<>();

    /** Jackson ObjectMapper for local JSON serialization (metadata, error messages). */
    private static final ObjectMapper jsonMapper = new ObjectMapper();

    /** Parses browser JSON to a tree for the SDK's raw-send path. */
    private static final ObjectMapper agentMapper = ObjectMappers.JSON_MAPPER;

    /**
     * Reflective handle to the SDK's private {@code V1WebSocketClient.sendMessage(Object)},
     * which serializes an arbitrary object with the SDK's own mapper and writes it
     * on the underlying (reconnecting) socket. We reuse this raw send path to
     * forward the browser's control messages <em>verbatim</em> (see
     * {@link #forwardClientMessage}); the SDK exposes no public raw-send method.
     */
    private static final Method DG_SEND_MESSAGE = resolveDgSendMessage();

    private static Method resolveDgSendMessage() {
        try {
            Method m = V1WebSocketClient.class.getDeclaredMethod("sendMessage", Object.class);
            m.setAccessible(true);
            return m;
        } catch (Exception e) {
            System.err.println("WARNING: could not resolve V1WebSocketClient.sendMessage(Object); "
                    + "client control messages cannot be forwarded verbatim: " + e.getMessage());
            return null;
        }
    }

    // ============================================================================
    // SESSION AUTH - JWT tokens for production security
    // ============================================================================

    /**
     * Generates a cryptographically random hex string for use as a session secret.
     *
     * @return 64-character hex string
     */
    private static String generateSessionSecret() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Creates a signed JWT session token with a 1-hour expiry.
     *
     * @return signed JWT string
     */
    private static String createSessionToken() {
        Algorithm algorithm = Algorithm.HMAC256(sessionSecret);
        return JWT.create()
                .withIssuedAt(Instant.now())
                .withExpiresAt(Instant.now().plusSeconds(JWT_EXPIRY_SECONDS))
                .sign(algorithm);
    }

    /**
     * Validates a JWT token string.
     *
     * @param token the JWT string to validate
     * @return true if the token is valid and not expired
     */
    private static boolean validateToken(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(sessionSecret);
            JWT.require(algorithm).build().verify(token);
            return true;
        } catch (JWTVerificationException e) {
            return false;
        }
    }

    /**
     * Validates JWT from WebSocket subprotocol: access_token.{jwt}
     * Returns the full protocol string if valid, null if invalid.
     *
     * @param protocols comma-separated list of WebSocket subprotocols
     * @return the valid access_token protocol string, or null
     */
    private static String validateWsToken(String protocols) {
        if (protocols == null || protocols.isEmpty()) {
            return null;
        }
        for (String proto : protocols.split(",")) {
            proto = proto.trim();
            if (proto.startsWith("access_token.")) {
                String token = proto.substring("access_token.".length());
                if (validateToken(token)) {
                    return proto;
                }
            }
        }
        return null;
    }

    // ============================================================================
    // WEBSOCKET HELPERS
    // ============================================================================

    /**
     * Returns a valid WebSocket close code, mapping reserved codes to 1000 (normal closure).
     *
     * @param code the original close code
     * @return a safe close code suitable for sending to clients
     */
    private static int getSafeCloseCode(int code) {
        if (code >= 1000 && code <= 4999 && !RESERVED_CLOSE_CODES.contains(code)) {
            return code;
        }
        return 1000;
    }

    /**
     * Forwards a JSON control message from the client to the Deepgram agent
     * websocket <em>verbatim</em>.
     *
     * <p>The message is serialized straight from the parsed JSON tree, not
     * round-tripped through the SDK's typed protocol classes (e.g.
     * {@code AgentV1Settings}). Those types re-emit their own constant
     * {@code type} discriminator <em>and</em> the incoming {@code type} they
     * captured in their additional-properties bag, so a round trip produces a
     * <b>duplicate {@code type}</b> key (at the top level and at nested union
     * variants such as {@code agent.listen.provider}). Deepgram rejects such a
     * payload with {@code UNPARSABLE_CLIENT_MESSAGE} and never emits
     * {@code SettingsApplied}. Forwarding the browser's JSON as-is preserves the
     * exact wire payload (a single {@code type} at every level) and honors the
     * transparent-proxy contract, where the browser owns the agent protocol.
     *
     * @param dg      the Deepgram agent websocket client
     * @param ctx     the browser websocket context
     * @param message the raw JSON text received from the browser
     */
    private static void forwardClientMessage(V1WebSocketClient dg, WsContext ctx, String message) {
        try {
            JsonNode node = agentMapper.readTree(message);
            if (!node.isObject()) {
                sendClientError(ctx, "Client message must be a JSON object", "INVALID_CLIENT_MESSAGE");
                return;
            }
            if (DG_SEND_MESSAGE == null) {
                System.err.println("Cannot forward client message; SDK raw-send path unavailable");
                sendClientError(ctx, "Deepgram connection is unavailable", "CONNECTION_FAILED");
                return;
            }
            // Hand the SDK's raw send path the parsed JSON tree so it serializes
            // it verbatim (no typed re-serialization, no duplicated `type`).
            DG_SEND_MESSAGE.invoke(dg, node);
        } catch (Exception e) {
            System.err.println("Error forwarding client message to Deepgram: " + e.getMessage());
            sendClientError(ctx, "Failed to forward client message", "PROVIDER_ERROR");
        }
    }

    /**
     * Sends an Error control message to the browser using the same shape the
     * previous raw proxy produced, so the frontend needs no changes.
     */
    private static void sendClientError(WsContext ctx, String description, String code) {
        try {
            Map<String, String> errorMsg = Map.of(
                    "type", "Error",
                    "description", description != null ? description : "Deepgram connection error",
                    "code", code);
            ctx.send(jsonMapper.writeValueAsString(errorMsg));
        } catch (Exception e) {
            System.err.println("Error sending error to client: " + e.getMessage());
        }
    }

    // ============================================================================
    // METADATA - deepgram.toml parser
    // ============================================================================

    /**
     * Reads and parses the [meta] section from deepgram.toml.
     *
     * @return a Map containing metadata fields, or null on error
     */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> readMetadata() {
        try {
            TomlMapper tomlMapper = new TomlMapper();
            Map<String, Object> config = tomlMapper.readValue(new File("deepgram.toml"), Map.class);
            Object meta = config.get("meta");
            if (meta instanceof Map) {
                return (Map<String, Object>) meta;
            }
            return null;
        } catch (Exception e) {
            System.err.println("Error reading deepgram.toml: " + e.getMessage());
            return null;
        }
    }

    // ============================================================================
    // WEBSOCKET BRIDGE HANDLER
    // ============================================================================

    /**
     * Configures the WebSocket bridge endpoint for voice agent connections.
     * Validates JWT auth, establishes an upstream Deepgram agent connection via
     * the SDK, and forwards messages bidirectionally.
     *
     * @param ws the Javalin WebSocket configuration
     */
    private static void voiceAgentWebSocket(WsConfig ws) {
        ws.onConnect(ctx -> {
            // Validate JWT from subprotocol
            String protocols = ctx.header("Sec-WebSocket-Protocol");
            String validProto = validateWsToken(protocols);
            if (validProto == null) {
                System.out.println("WebSocket auth failed: invalid or missing token");
                ctx.closeSession(4401, "Unauthorized");
                return;
            }

            System.out.println("Client connected to /api/voice-agent");
            activeConnections.add(ctx);

            try {
                // Create the Deepgram agent websocket client for this connection
                V1WebSocketClient dg = deepgram.agent().v1().v1WebSocket();
                deepgramSessions.put(ctx, dg);

                // Deepgram -> browser: forward every JSON event verbatim (before typed
                // dispatch) so the frontend sees the exact agent protocol as before.
                dg.onMessage(raw -> {
                    try {
                        if (ctx.session.isOpen()) {
                            ctx.send(raw);
                        }
                    } catch (Exception e) {
                        System.err.println("Error forwarding text to client: " + e.getMessage());
                    }
                });

                // Deepgram -> browser: forward binary agent audio
                dg.onAgentV1Audio(audio -> {
                    try {
                        if (ctx.session.isOpen()) {
                            ctx.send(ByteBuffer.wrap(audio.toByteArray()));
                        }
                    } catch (Exception e) {
                        System.err.println("Error forwarding binary to client: " + e.getMessage());
                    }
                });

                dg.onConnected(() -> System.out.println("Connected to Deepgram Agent API"));

                dg.onError(error -> {
                    System.err.println("Deepgram WebSocket error: " + error.getMessage());
                    if (ctx.session.isOpen()) {
                        sendClientError(ctx, error.getMessage(), "PROVIDER_ERROR");
                    }
                });

                dg.onDisconnected(reason -> {
                    System.out.println("Deepgram connection closed: " + reason.getCode() + " "
                            + (reason.getReason() != null ? reason.getReason() : ""));
                    if (ctx.session.isOpen()) {
                        try {
                            ctx.closeSession(getSafeCloseCode(reason.getCode()),
                                    reason.getReason() != null ? reason.getReason() : "");
                        } catch (Exception e) {
                            System.err.println("Error closing client connection: " + e.getMessage());
                        }
                    }
                });

                // Connect to the Deepgram Voice Agent API
                System.out.println("Initiating Deepgram connection...");
                dg.connect().whenComplete((v, err) -> {
                    if (err != null) {
                        System.err.println("Deepgram connection failed to open: " + err.getMessage());
                        if (ctx.session.isOpen()) {
                            sendClientError(ctx, "Failed to establish agent connection", "CONNECTION_FAILED");
                            ctx.closeSession(1011, "Failed to connect to Deepgram");
                        }
                    }
                });
            } catch (Exception e) {
                System.err.println("Error setting up bridge: " + e.getMessage());
                sendClientError(ctx, "Failed to establish agent connection", "CONNECTION_FAILED");
                ctx.closeSession(1011, "Failed to connect to Deepgram");
                deepgramSessions.remove(ctx);
                activeConnections.remove(ctx);
            }
        });

        // Forward text (control) messages from client to Deepgram
        ws.onMessage(ctx -> {
            V1WebSocketClient dg = deepgramSessions.get(ctx);
            if (dg != null) {
                forwardClientMessage(dg, ctx, ctx.message());
            }
        });

        // Forward binary audio from client to Deepgram
        ws.onBinaryMessage(ctx -> {
            V1WebSocketClient dg = deepgramSessions.get(ctx);
            if (dg != null) {
                byte[] data = ctx.data();
                int offset = ctx.offset();
                int length = ctx.length();
                try {
                    dg.sendMedia(ByteString.of(data, offset, length));
                } catch (Exception e) {
                    System.err.println("Error sending audio to Deepgram: " + e.getMessage());
                }
            }
        });

        // Handle client disconnect
        ws.onClose(ctx -> {
            System.out.println("Client disconnected: " + ctx.status() + " " + ctx.reason());
            V1WebSocketClient dg = deepgramSessions.remove(ctx);
            if (dg != null) {
                dg.disconnect();
            }
            activeConnections.remove(ctx);
        });

        // Handle client errors
        ws.onError(ctx -> {
            System.err.println("Client WebSocket error: " +
                    (ctx.error() != null ? ctx.error().getMessage() : "unknown"));
            V1WebSocketClient dg = deepgramSessions.remove(ctx);
            if (dg != null) {
                dg.disconnect();
            }
            activeConnections.remove(ctx);
        });
    }

    // ============================================================================
    // GRACEFUL SHUTDOWN
    // ============================================================================

    /**
     * Performs graceful shutdown: closes all active WebSocket connections
     * and disconnects all Deepgram agent sessions.
     *
     * @param signal the signal name that triggered shutdown
     */
    private static void gracefulShutdown(String signal) {
        System.out.println("\n" + signal + " signal received: starting graceful shutdown...");

        // Close all active client WebSocket connections
        System.out.println("Closing " + activeConnections.size() + " active WebSocket connection(s)...");
        for (WsContext ctx : activeConnections) {
            try {
                ctx.closeSession(1001, "Server shutting down");
            } catch (Exception e) {
                System.err.println("Error closing WebSocket: " + e.getMessage());
            }
        }

        // Disconnect all Deepgram sessions
        for (V1WebSocketClient dg : deepgramSessions.values()) {
            try {
                dg.disconnect();
            } catch (Exception e) {
                System.err.println("Error closing Deepgram session: " + e.getMessage());
            }
        }

        System.out.println("Shutdown complete");
    }

    // ============================================================================
    // MAIN
    // ============================================================================

    /**
     * Application entry point. Loads configuration, initializes the Deepgram SDK
     * client, registers HTTP and WebSocket routes, and starts the Javalin server.
     *
     * @param args command-line arguments (unused)
     */
    public static void main(String[] args) {
        // Load environment variables from .env file
        Dotenv dotenv = Dotenv.configure()
                .ignoreIfMissing()
                .load();

        // Validate required environment variables
        deepgramApiKey = dotenv.get("DEEPGRAM_API_KEY");
        if (deepgramApiKey == null || deepgramApiKey.isEmpty()) {
            System.err.println("ERROR: DEEPGRAM_API_KEY environment variable is required");
            System.err.println("Please copy sample.env to .env and add your API key");
            System.exit(1);
        }

        // Fail fast if the reflective raw-send handle could not be resolved.
        // forwardClientMessage relies on the SDK's private
        // V1WebSocketClient.sendMessage(Object) to forward the browser's control
        // messages (including the initial Settings) verbatim. Without it the
        // server would still start and audio would flow, but Settings would
        // never be forwarded, so the agent would never be configured and never
        // speak — a silent failure. Refuse to start instead. (See S2: the typed
        // public senders emit a duplicated `type` the agent rejects, which is
        // why this reflection exists; remove it once the SDK exposes a public
        // raw/verbatim send.)
        if (DG_SEND_MESSAGE == null) {
            System.err.println("ERROR: could not resolve the SDK's V1WebSocketClient.sendMessage(Object); "
                    + "client control messages cannot be forwarded. This usually means the pinned "
                    + "deepgram-java-sdk version changed that method's name/signature.");
            System.exit(1);
        }

        // Load optional configuration
        String portStr = dotenv.get("PORT", "8081");
        port = Integer.parseInt(portStr);
        host = dotenv.get("HOST", "0.0.0.0");

        sessionSecret = dotenv.get("SESSION_SECRET");
        if (sessionSecret == null || sessionSecret.isEmpty()) {
            sessionSecret = generateSessionSecret();
        }

        // Initialize the Deepgram SDK client for outbound agent connections
        deepgram = DeepgramClient.builder().apiKey(deepgramApiKey).build();

        // Create Javalin app with CORS enabled
        Javalin app = Javalin.create(config -> {
            config.bundledPlugins.enableCors(cors -> {
                cors.addRule(rule -> {
                    rule.anyHost();
                });
            });
        });

        // ====================================================================
        // HTTP ROUTES
        // ====================================================================

        // GET /api/session - Issue signed JWT session token
        app.get("/api/session", ctx -> {
            String token = createSessionToken();
            ctx.json(Map.of("token", token));
        });

        // GET /health - Health check
        app.get("/health", ctx -> {
            ctx.json(Map.of("status", "ok"));
        });

        // GET /api/metadata - Project metadata from deepgram.toml
        app.get("/api/metadata", ctx -> {
            Map<String, Object> meta = readMetadata();
            if (meta == null) {
                ctx.status(500).json(Map.of(
                        "error", "INTERNAL_SERVER_ERROR",
                        "message", "Failed to read metadata from deepgram.toml"
                ));
                return;
            }
            ctx.json(meta);
        });

        // ====================================================================
        // WEBSOCKET ROUTES
        // ====================================================================

        // WS /api/voice-agent - WebSocket bridge to Deepgram Agent API
        app.ws("/api/voice-agent", App::voiceAgentWebSocket);

        // ====================================================================
        // SHUTDOWN HANDLING
        // ====================================================================

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            gracefulShutdown("SHUTDOWN");
            app.stop();
        }));

        // ====================================================================
        // START SERVER
        // ====================================================================

        app.start(host, port);

        String separator = "=".repeat(70);
        System.out.println("\n" + separator);
        System.out.println("Backend API Server running at http://localhost:" + port);
        System.out.println();
        System.out.println("GET  /api/session");
        System.out.println("WS   /api/voice-agent (auth required)");
        System.out.println("GET  /api/metadata");
        System.out.println("GET  /health");
        System.out.println(separator + "\n");
    }
}
