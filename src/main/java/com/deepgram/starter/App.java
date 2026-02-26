/**
 * Java Voice Agent Starter - Backend Server
 *
 * Simple WebSocket proxy to Deepgram's Voice Agent API using Javalin.
 * Forwards all messages (JSON and binary) bidirectionally between client and Deepgram.
 *
 * Key Features:
 * - WebSocket proxy to Deepgram Voice Agent API (agent.deepgram.com)
 * - JWT session authentication via WebSocket subprotocol
 * - Project metadata from deepgram.toml
 * - Graceful shutdown with connection tracking
 *
 * Routes:
 *   GET  /api/session       - Issue signed session token
 *   GET  /api/metadata      - Project metadata from deepgram.toml
 *   WS   /api/voice-agent   - WebSocket proxy to Deepgram Agent API (auth required)
 *   GET  /health            - Health check
 */
package com.deepgram.starter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.toml.TomlMapper;
import io.github.cdimascio.dotenv.Dotenv;
import io.javalin.Javalin;
import io.javalin.websocket.WsConfig;
import io.javalin.websocket.WsContext;
import org.eclipse.jetty.websocket.client.WebSocketClient;
import org.eclipse.jetty.websocket.api.Callback;
import org.eclipse.jetty.websocket.api.Session;
import org.eclipse.jetty.websocket.api.annotations.*;

import java.io.File;
import java.net.URI;
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
 * Manages HTTP routes, WebSocket proxy, and server lifecycle.
 */
public class App {

    /** Deepgram API key for authenticating upstream connections. */
    private static String deepgramApiKey;

    /** Deepgram Voice Agent WebSocket URL. */
    private static final String DEEPGRAM_AGENT_URL = "wss://agent.deepgram.com/v1/agent/converse";

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

    /** Tracks Deepgram sessions keyed by client session ID for cleanup. */
    private static final Map<String, DeepgramSession> deepgramSessions = new ConcurrentHashMap<>();

    /** Shared Jetty WebSocket client for outbound Deepgram connections. */
    private static WebSocketClient wsClient;

    /** Jackson ObjectMapper for JSON serialization. */
    private static final ObjectMapper jsonMapper = new ObjectMapper();

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

    // ============================================================================
    // DEEPGRAM WEBSOCKET SESSION
    // ============================================================================

    /**
     * Jetty WebSocket endpoint that connects to Deepgram's Voice Agent API.
     * Forwards all messages bidirectionally between the client and Deepgram.
     */
    @WebSocket
    public static class DeepgramSession {
        private WsContext clientCtx;
        private Session deepgramSession;
        private String sessionId;

        public DeepgramSession() {}

        /**
         * Sets the client context for bidirectional message forwarding.
         *
         * @param ctx    the Javalin WebSocket context
         * @param sessId unique session identifier for tracking
         */
        public void setClientContext(WsContext ctx, String sessId) {
            this.clientCtx = ctx;
            this.sessionId = sessId;
        }

        @OnWebSocketOpen
        public void onOpen(Session session) {
            this.deepgramSession = session;
            System.out.println("Connected to Deepgram Agent API");
        }

        @OnWebSocketMessage
        public void onTextMessage(Session session, String message) {
            // Forward JSON messages from Deepgram to client
            if (clientCtx != null) {
                try {
                    clientCtx.send(message);
                } catch (Exception e) {
                    System.err.println("Error forwarding text to client: " + e.getMessage());
                }
            }
        }

        @OnWebSocketMessage
        public void onBinaryMessage(Session session, ByteBuffer payload, Callback callback) {
            // Forward binary audio from Deepgram to client
            if (clientCtx != null) {
                try {
                    byte[] data = new byte[payload.remaining()];
                    payload.get(data);
                    clientCtx.send(ByteBuffer.wrap(data));
                } catch (Exception e) {
                    System.err.println("Error forwarding binary to client: " + e.getMessage());
                }
            }
            callback.succeed();
        }

        @OnWebSocketError
        public void onError(Session session, Throwable cause) {
            System.err.println("Deepgram WebSocket error: " + cause.getMessage());
            if (clientCtx != null) {
                try {
                    Map<String, String> errorMsg = Map.of(
                            "type", "Error",
                            "description", cause.getMessage() != null ? cause.getMessage() : "Deepgram connection error",
                            "code", "PROVIDER_ERROR"
                    );
                    clientCtx.send(jsonMapper.writeValueAsString(errorMsg));
                } catch (Exception e) {
                    System.err.println("Error sending error to client: " + e.getMessage());
                }
            }
        }

        @OnWebSocketClose
        public void onClose(int statusCode, String reason) {
            System.out.println("Deepgram connection closed: " + statusCode + " " + (reason != null ? reason : ""));
            if (clientCtx != null) {
                try {
                    int safeCode = getSafeCloseCode(statusCode);
                    clientCtx.closeSession(safeCode, reason != null ? reason : "");
                } catch (Exception e) {
                    System.err.println("Error closing client connection: " + e.getMessage());
                }
            }
            cleanup();
        }

        /**
         * Sends a text message to Deepgram.
         *
         * @param message the text message to send
         */
        public void sendText(String message) {
            if (deepgramSession != null && deepgramSession.isOpen()) {
                deepgramSession.sendText(message, Callback.NOOP);
            }
        }

        /**
         * Sends binary data to Deepgram.
         *
         * @param data the binary data to send
         */
        public void sendBinary(ByteBuffer data) {
            if (deepgramSession != null && deepgramSession.isOpen()) {
                deepgramSession.sendBinary(data, Callback.NOOP);
            }
        }

        /**
         * Closes the Deepgram connection.
         */
        public void close() {
            if (deepgramSession != null && deepgramSession.isOpen()) {
                deepgramSession.close(1000, "Client disconnected", Callback.NOOP);
            }
        }

        private void cleanup() {
            if (sessionId != null) {
                deepgramSessions.remove(sessionId);
            }
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
    // WEBSOCKET PROXY HANDLER
    // ============================================================================

    /**
     * Configures the WebSocket proxy endpoint for voice agent connections.
     * Validates JWT auth, establishes upstream Deepgram connection, and
     * forwards all messages bidirectionally.
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

            String sessionId = ctx.getSessionId();

            try {
                // Create Deepgram session handler
                DeepgramSession dgSession = new DeepgramSession();
                dgSession.setClientContext(ctx, sessionId);
                deepgramSessions.put(sessionId, dgSession);

                // Connect to Deepgram Voice Agent API with auth header
                System.out.println("Initiating Deepgram connection...");
                org.eclipse.jetty.websocket.client.ClientUpgradeRequest request =
                        new org.eclipse.jetty.websocket.client.ClientUpgradeRequest();
                request.setHeader("Authorization", "Token " + deepgramApiKey);

                wsClient.connect(dgSession, URI.create(DEEPGRAM_AGENT_URL), request);
            } catch (Exception e) {
                System.err.println("Error setting up proxy: " + e.getMessage());
                try {
                    Map<String, String> errorMsg = Map.of(
                            "type", "Error",
                            "description", "Failed to establish proxy connection",
                            "code", "CONNECTION_FAILED"
                    );
                    ctx.send(jsonMapper.writeValueAsString(errorMsg));
                } catch (Exception ex) {
                    System.err.println("Error sending error message: " + ex.getMessage());
                }
                ctx.closeSession(1011, "Failed to connect to Deepgram");
                activeConnections.remove(ctx);
            }
        });

        // Forward text messages from client to Deepgram
        ws.onMessage(ctx -> {
            String sessionId = ctx.getSessionId();
            DeepgramSession dgSession = deepgramSessions.get(sessionId);
            if (dgSession != null) {
                dgSession.sendText(ctx.message());
            }
        });

        // Forward binary messages from client to Deepgram
        ws.onBinaryMessage((ctx, data, offset, length) -> {
            String sessionId = ctx.getSessionId();
            DeepgramSession dgSession = deepgramSessions.get(sessionId);
            if (dgSession != null) {
                ByteBuffer buffer = ByteBuffer.wrap(data, offset, length);
                dgSession.sendBinary(buffer);
            }
        });

        // Handle client disconnect
        ws.onClose(ctx -> {
            System.out.println("Client disconnected: " + ctx.status() + " " + ctx.reason());
            String sessionId = ctx.getSessionId();
            DeepgramSession dgSession = deepgramSessions.remove(sessionId);
            if (dgSession != null) {
                dgSession.close();
            }
            activeConnections.remove(ctx);
        });

        // Handle client errors
        ws.onError(ctx -> {
            System.err.println("Client WebSocket error: " +
                    (ctx.error() != null ? ctx.error().getMessage() : "unknown"));
            String sessionId = ctx.getSessionId();
            DeepgramSession dgSession = deepgramSessions.remove(sessionId);
            if (dgSession != null) {
                dgSession.close();
            }
            activeConnections.remove(ctx);
        });
    }

    // ============================================================================
    // GRACEFUL SHUTDOWN
    // ============================================================================

    /**
     * Performs graceful shutdown: closes all active WebSocket connections
     * and stops the Jetty WebSocket client.
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

        // Close all Deepgram sessions
        for (DeepgramSession dgSession : deepgramSessions.values()) {
            try {
                dgSession.close();
            } catch (Exception e) {
                System.err.println("Error closing Deepgram session: " + e.getMessage());
            }
        }

        // Stop the WebSocket client
        if (wsClient != null) {
            try {
                wsClient.stop();
            } catch (Exception e) {
                System.err.println("Error stopping WebSocket client: " + e.getMessage());
            }
        }

        System.out.println("Shutdown complete");
    }

    // ============================================================================
    // MAIN
    // ============================================================================

    /**
     * Application entry point. Loads configuration, initializes the Jetty WebSocket
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

        // Load optional configuration
        String portStr = dotenv.get("PORT", "8081");
        port = Integer.parseInt(portStr);
        host = dotenv.get("HOST", "0.0.0.0");

        sessionSecret = dotenv.get("SESSION_SECRET");
        if (sessionSecret == null || sessionSecret.isEmpty()) {
            sessionSecret = generateSessionSecret();
        }

        // Initialize Jetty WebSocket client for outbound Deepgram connections
        wsClient = new WebSocketClient();
        try {
            wsClient.start();
        } catch (Exception e) {
            System.err.println("Failed to start WebSocket client: " + e.getMessage());
            System.exit(1);
        }

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

        // WS /api/voice-agent - WebSocket proxy to Deepgram Agent API
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
