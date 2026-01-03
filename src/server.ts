/**
 * ExportMyChat Backend Server
 *
 * Handles Google OAuth and Drive API proxy for the browser extension.
 * This solves the extension ID / redirect URI problem by:
 * 1. Using a fixed backend URL for OAuth redirect (works in ALL browsers)
 * 2. Storing refresh tokens server-side
 * 3. Proxying all Drive API calls through the backend
 */

import express, {
    Request,
    Response,
    NextFunction,
    RequestHandler,
} from "express";
import cors from "cors";
import crypto from "crypto";
import { google } from "googleapis";
import dotenv from "dotenv";
import { v4 as uuidv4 } from "uuid";

dotenv.config();

const app = express();
const PORT = 3000;
const BACKEND_URL = process.env.BACKEND_URL || `http://localhost:${PORT}`;

// Google OAuth configuration
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID!;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET!;
const REDIRECT_URI = `${BACKEND_URL}/oauth/callback`;

const SCOPES = [
    "https://www.googleapis.com/auth/drive.file",
    "https://www.googleapis.com/auth/drive.appdata",
    "https://www.googleapis.com/auth/userinfo.email",
];

// In-memory session store (use Redis/DB in production)
interface Session {
    userId: string;
    email: string;
    accessToken: string;
    refreshToken: string;
    expiresAt: number;
    createdAt: number;
}

const sessions = new Map<string, Session>();
const pendingOAuth = new Map<
    string,
    { state: string; extensionOrigin: string; timestamp: number }
>();

// Session token encryption (optional but recommended)
const SESSION_SECRET =
    process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");

function generateSessionToken(): string {
    return crypto.randomBytes(32).toString("hex");
}

function hashToken(token: string): string {
    return crypto
        .createHmac("sha256", SESSION_SECRET)
        .update(token)
        .digest("hex");
}

// CORS configuration
const corsOptions: cors.CorsOptions = {
    origin: (origin, callback) => {
        // Allow requests from browser extensions and configured origins
        const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(",") || [];

        // Always allow no origin (server-to-server) and extension origins
        if (
            !origin ||
            origin.startsWith("chrome-extension://") ||
            origin.startsWith("moz-extension://") ||
            origin.startsWith("safari-web-extension://") ||
            allowedOrigins.some((allowed) => origin.startsWith(allowed)) ||
            allowedOrigins.includes("*")
        ) {
            callback(null, true);
        } else {
            callback(new Error("Not allowed by CORS"));
        }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Session-Token"],
};

app.use(cors(corsOptions));
app.use(express.json({ limit: "10mb" }));
app.use(express.static("public"));

// Request logging middleware
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
    next();
});

// Auth middleware
interface AuthenticatedRequest extends Request {
    session?: Session;
    oauth2Client?: InstanceType<typeof google.auth.OAuth2>;
}

const authMiddleware: RequestHandler = async (req, res, next) => {
    const authReq = req as AuthenticatedRequest;
    const sessionToken = req.headers["x-session-token"] as string;

    if (!sessionToken) {
        return res.status(401).json({ error: "No session token provided" });
    }

    const hashedToken = hashToken(sessionToken);
    const session = sessions.get(hashedToken);

    if (!session) {
        return res.status(401).json({ error: "Invalid session token" });
    }

    // Check if access token needs refresh
    if (session.expiresAt < Date.now() + 60000) {
        try {
            const oauth2Client = new google.auth.OAuth2(
                GOOGLE_CLIENT_ID,
                GOOGLE_CLIENT_SECRET,
                REDIRECT_URI
            );
            oauth2Client.setCredentials({
                refresh_token: session.refreshToken,
            });

            const { credentials } = await oauth2Client.refreshAccessToken();
            session.accessToken = credentials.access_token!;
            session.expiresAt = credentials.expiry_date || Date.now() + 3600000;
            sessions.set(hashedToken, session);
        } catch (error) {
            console.error("Token refresh failed:", error);
            sessions.delete(hashedToken);
            return res
                .status(401)
                .json({ error: "Session expired, please re-authenticate" });
        }
    }

    // Create OAuth2 client with current credentials
    const oauth2Client = new google.auth.OAuth2(
        GOOGLE_CLIENT_ID,
        GOOGLE_CLIENT_SECRET,
        REDIRECT_URI
    );
    oauth2Client.setCredentials({
        access_token: session.accessToken,
        refresh_token: session.refreshToken,
    });

    authReq.session = session;
    authReq.oauth2Client = oauth2Client;
    next();
};

// ============================================
// OAuth Routes
// ============================================

/**
 * Start OAuth flow
 * Extension opens this URL in a new tab/popup
 */
app.get("/oauth/google", (req: Request, res: Response) => {
    const state = uuidv4();

    // Store pending OAuth state
    pendingOAuth.set(state, {
        state,
        extensionOrigin: "",
        timestamp: Date.now(),
    });

    // Clean up old pending requests (older than 10 minutes)
    const tenMinutesAgo = Date.now() - 10 * 60 * 1000;
    for (const [key, value] of pendingOAuth.entries()) {
        if (value.timestamp < tenMinutesAgo) {
            pendingOAuth.delete(key);
        }
    }

    const oauth2Client = new google.auth.OAuth2(
        GOOGLE_CLIENT_ID,
        GOOGLE_CLIENT_SECRET,
        REDIRECT_URI
    );

    const authUrl = oauth2Client.generateAuthUrl({
        access_type: "offline",
        scope: SCOPES,
        state,
        prompt: "consent", // Force consent to get refresh token
    });

    res.redirect(authUrl);
});

/**
 * OAuth callback from Google
 * Exchanges code for tokens and creates a session
 */
app.get("/oauth/callback", async (req: Request, res: Response) => {
    const { code, state, error } = req.query;

    if (error) {
        return res.send(renderErrorPage(`OAuth error: ${error}`));
    }

    if (!code || !state) {
        return res.send(renderErrorPage("Missing code or state parameter"));
    }

    const pending = pendingOAuth.get(state as string);
    if (!pending) {
        return res.send(renderSuccessPage("Invalid or expired OAuth state", "kanhaiyadav.me@gmail.com"));
    }
    pendingOAuth.delete(state as string);

    try {
        const oauth2Client = new google.auth.OAuth2(
            GOOGLE_CLIENT_ID,
            GOOGLE_CLIENT_SECRET,
            REDIRECT_URI
        );

        const { tokens } = await oauth2Client.getToken(code as string);
        oauth2Client.setCredentials(tokens);

        // Get user info
        const oauth2 = google.oauth2({ version: "v2", auth: oauth2Client });
        const userInfo = await oauth2.userinfo.get();

        // Create session
        const sessionToken = generateSessionToken();
        const hashedToken = hashToken(sessionToken);

        const session: Session = {
            userId: userInfo.data.id!,
            email: userInfo.data.email!,
            accessToken: tokens.access_token!,
            refreshToken: tokens.refresh_token!,
            expiresAt: tokens.expiry_date || Date.now() + 3600000,
            createdAt: Date.now(),
        };

        sessions.set(hashedToken, session);

        // Return HTML page that sends the session token to the extension
        res.send(renderSuccessPage(sessionToken, userInfo.data.email!));
    } catch (err) {
        console.error("OAuth callback error:", err);
        res.send(renderErrorPage("Failed to complete authentication"));
    }
});

/**
 * Validate session and get user info
 */
app.get("/auth/status", authMiddleware, (req: Request, res: Response) => {
    const authReq = req as AuthenticatedRequest;
    res.json({
        authenticated: true,
        email: authReq.session!.email,
        userId: authReq.session!.userId,
    });
});

/**
 * Sign out - invalidate session
 */
app.post("/auth/signout", (req: Request, res: Response) => {
    const sessionToken = req.headers["x-session-token"] as string;

    if (sessionToken) {
        const hashedToken = hashToken(sessionToken);
        const session = sessions.get(hashedToken);

        if (session) {
            // Revoke the token with Google
            try {
                const oauth2Client = new google.auth.OAuth2(
                    GOOGLE_CLIENT_ID,
                    GOOGLE_CLIENT_SECRET,
                    REDIRECT_URI
                );
                oauth2Client.revokeToken(session.accessToken);
            } catch (e) {
                // Ignore revocation errors
            }
            sessions.delete(hashedToken);
        }
    }

    res.json({ success: true });
});

// ============================================
// Google Drive API Proxy Routes
// ============================================

const DRIVE_APP_FOLDER = "ExportMyChat_Data";

/**
 * Get or create app folder
 */
async function getOrCreateAppFolder(
    drive: ReturnType<typeof google.drive>
): Promise<string> {
    // Search for existing folder
    const searchResponse = await drive.files.list({
        q: `name='${DRIVE_APP_FOLDER}' and mimeType='application/vnd.google-apps.folder' and trashed=false`,
        fields: "files(id, name)",
    });

    if (searchResponse.data.files && searchResponse.data.files.length > 0) {
        return searchResponse.data.files[0].id!;
    }

    // Create folder
    const createResponse = await drive.files.create({
        requestBody: {
            name: DRIVE_APP_FOLDER,
            mimeType: "application/vnd.google-apps.folder",
        },
        fields: "id",
    });

    return createResponse.data.id!;
}

/**
 * Find a file in the app folder
 */
async function findFile(
    drive: ReturnType<typeof google.drive>,
    folderId: string,
    fileName: string
) {
    const response = await drive.files.list({
        q: `name='${fileName}' and '${folderId}' in parents and trashed=false`,
        fields: "files(id, name, modifiedTime)",
    });

    return response.data.files?.[0] || null;
}

/**
 * List files in app folder
 */
app.get("/drive/files", authMiddleware, async (req: Request, res: Response) => {
    const authReq = req as AuthenticatedRequest;
    try {
        const drive = google.drive({
            version: "v3",
            auth: authReq.oauth2Client,
        });
        const folderId = await getOrCreateAppFolder(drive);

        const response = await drive.files.list({
            q: `'${folderId}' in parents and trashed=false`,
            fields: "files(id, name, modifiedTime, size)",
        });

        res.json({ files: response.data.files || [] });
    } catch (error) {
        console.error("List files error:", error);
        res.status(500).json({ error: "Failed to list files" });
    }
});

/**
 * Get file content
 */
app.get(
    "/drive/files/:fileName",
    authMiddleware,
    async (req: Request, res: Response) => {
        const authReq = req as AuthenticatedRequest;
        try {
            const drive = google.drive({
                version: "v3",
                auth: authReq.oauth2Client,
            });
            const folderId = await getOrCreateAppFolder(drive);
            const file = await findFile(drive, folderId, req.params.fileName);

            if (!file) {
                return res.status(404).json({ error: "File not found" });
            }

            const response = await drive.files.get({
                fileId: file.id!,
                alt: "media",
            });

            res.json(response.data);
        } catch (error) {
            console.error("Get file error:", error);
            res.status(500).json({ error: "Failed to get file" });
        }
    }
);

/**
 * Upload/update file
 */
app.put(
    "/drive/files/:fileName",
    authMiddleware,
    async (req: Request, res: Response) => {
        const authReq = req as AuthenticatedRequest;
        try {
            const drive = google.drive({
                version: "v3",
                auth: authReq.oauth2Client,
            });
            const folderId = await getOrCreateAppFolder(drive);
            const existingFile = await findFile(
                drive,
                folderId,
                req.params.fileName
            );

            const content = JSON.stringify(req.body);
            const media = {
                mimeType: "application/json",
                body: content,
            };

            let response;
            if (existingFile) {
                // Update existing file
                response = await drive.files.update({
                    fileId: existingFile.id!,
                    media,
                    fields: "id, name, modifiedTime",
                });
            } else {
                // Create new file
                response = await drive.files.create({
                    requestBody: {
                        name: req.params.fileName,
                        parents: [folderId],
                        mimeType: "application/json",
                    },
                    media,
                    fields: "id, name, modifiedTime",
                });
            }

            res.json({ file: response.data });
        } catch (error) {
            console.error("Upload file error:", error);
            res.status(500).json({ error: "Failed to upload file" });
        }
    }
);

/**
 * Delete file
 */
app.delete(
    "/drive/files/:fileName",
    authMiddleware,
    async (req: Request, res: Response) => {
        const authReq = req as AuthenticatedRequest;
        try {
            const drive = google.drive({
                version: "v3",
                auth: authReq.oauth2Client,
            });
            const folderId = await getOrCreateAppFolder(drive);
            const file = await findFile(drive, folderId, req.params.fileName);

            if (!file) {
                return res.status(404).json({ error: "File not found" });
            }

            await drive.files.delete({ fileId: file.id! });
            res.json({ success: true });
        } catch (error) {
            console.error("Delete file error:", error);
            res.status(500).json({ error: "Failed to delete file" });
        }
    }
);

/**
 * Check if cloud data exists
 */
app.get(
    "/drive/has-data",
    authMiddleware,
    async (req: Request, res: Response) => {
        const authReq = req as AuthenticatedRequest;
        try {
            const drive = google.drive({
                version: "v3",
                auth: authReq.oauth2Client,
            });
            const folderId = await getOrCreateAppFolder(drive);

            const chatsFile = await findFile(drive, folderId, "chats.json");
            const presetsFile = await findFile(drive, folderId, "presets.json");

            res.json({ hasData: !!(chatsFile || presetsFile) });
        } catch (error) {
            console.error("Check data error:", error);
            res.status(500).json({ error: "Failed to check cloud data" });
        }
    }
);

/**
 * Delete all app data
 */
app.delete(
    "/drive/all-data",
    authMiddleware,
    async (req: Request, res: Response) => {
        const authReq = req as AuthenticatedRequest;
        try {
            const drive = google.drive({
                version: "v3",
                auth: authReq.oauth2Client,
            });
            const folderId = await getOrCreateAppFolder(drive);

            const filesToDelete = [
                "chats.json",
                "presets.json",
                "deletions.json",
            ];

            for (const fileName of filesToDelete) {
                const file = await findFile(drive, folderId, fileName);
                if (file) {
                    await drive.files.delete({ fileId: file.id! });
                }
            }

            res.json({ success: true });
        } catch (error) {
            console.error("Delete all data error:", error);
            res.status(500).json({ error: "Failed to delete all data" });
        }
    }
);

// ============================================
// Helper Functions for HTML Responses
// ============================================

function renderSuccessPage(sessionToken: string, email: string): string {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authentication Successful - ExportMyChat</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <link rel="shortcut icon" href="/favicon.ico" type="image/x-icon">
    <link rel="icon" href="/favicon.ico" type="image/x-icon">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
            background: #f0f2f5;
            position: relative;
        }
        .background-pattern {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(135deg, #f59e0b 0%, #ffb900 50%, #fbbf24 100%);
            z-index: -1;
        }
        .background-pattern::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.05'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
            opacity: 0.5;
        }
        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        .container {
            background: white;
            padding: 48px 40px;
            border-radius: 24px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.1);
            text-align: center;
            max-width: 480px;
            width: 100%;
            animation: slideUp 0.6s ease-out;
        }
        .logo {
            width: 88px;
            height: 88px;
            margin: 0 auto 24px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .logo img {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }
        .success-icon {
            width: 72px;
            height: 72px;
            margin: 0 auto 24px;
            border-radius: 50%;
            background: linear-gradient(135deg, #10B981 0%, #059669 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 8px 16px -4px rgba(16, 185, 129, 0.3);
        }
        .success-icon i {
            color: white;
            font-size: 32px;
        }
        h1 {
            color: #111827;
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 12px;
            letter-spacing: -0.025em;
        }
        .subtitle {
            color: #6b7280;
            font-size: 0.9rem;
            margin-bottom: 18px;
        }
        .email {
            display: inline-block;
            background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%);
            color: #d97706;
            padding: 8px 16px;
            border-radius: 12px;
            font-weight: 600;
            margin-bottom: 28px;
            border: 1px solid #fde68a;
        }
        .instructions {
            background: #f9fafb;
            padding: 20px 24px;
            border-radius: 16px;
            margin-bottom: 24px;
            border: 1px solid #e5e7eb;
        }
        .instructions p {
            color: #4b5563;
            font-size: 0.95rem;
            line-height: 1.6;
            margin-bottom: 8px;
        }
        .instructions p:last-child {
            margin-bottom: 0;
        }
        .token-display {
            background: #1F2937;
            color: #10B981;
            padding: 16px;
            border-radius: 12px;
            font-family: 'Monaco', 'Courier New', monospace;
            font-size: 13px;
            word-break: break-all;
            margin: 20px 0;
            display: none;
            border: 2px solid #374151;
        }
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            padding: 14px 28px;
            background: #111827;
            color: white;
            border: none;
            border-radius: 12px;
            font-weight: 600;
            font-size: 1rem;
            cursor: pointer;
            transition: all 0.25s ease;
            margin-top: 8px;
            font-family: 'Inter', sans-serif;
        }
        .btn:hover {
            background: #1f2937;
            transform: translateY(-2px);
            box-shadow: 0 8px 16px -4px rgba(0, 0, 0, 0.25);
        }
        .btn i {
            font-size: 16px;
        }
        .footer-note {
            margin-top: 28px;
            padding-top: 24px;
            border-top: 1px solid #e5e7eb;
            color: #9ca3af;
            font-size: 0.875rem;
        }
        .success-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: #d1fae5;
            color: #065f46;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.875rem;
            font-weight: 600;
            margin-bottom: 20px;
        }
        .success-badge i {
            color: #10B981;
        }
        @media (max-width: 640px) {
            .container {
                padding: 36px 28px;
            }
            h1 {
                font-size: 1.75rem;
            }
        }
    </style>
</head>
<body>
    <div class="background-pattern"></div>
    <div class="container">
        <div class="logo">
            <img src="/logo.png" alt="ExportMyChat" />
        </div>
        <div class="email">
        <i class="fas fa-user" style="margin-right:8px;color:#d97706;"></i>${email}
        </div>
        <div class="instructions">
        <div class="success-badge">
            <i class="fas fa-check-circle"></i>
            Authentication Successful
        </div>
            <p><strong>✓ Session token copied to clipboard</strong></p>
            <p>Return to your browser extension and paste the token in the modal to complete the setup.</p>
        </div>
        <div class="token-display" id="token">${sessionToken}</div>
        <button class="btn" onclick="copyToken()">
            <i class="fas fa-copy"></i>
            Copy Token Again
        </button>
        <div class="footer-note">
            <i class="fas fa-info-circle"></i> You can safely close this window after copying the token
        </div>
    </div>
    <script>
        const token = '${sessionToken}';
        
        // Auto-copy to clipboard
        navigator.clipboard.writeText(token).catch(() => {
            document.getElementById('token').style.display = 'block';
        });

        function copyToken() {
            const btn = event.target.closest('button');
            const originalContent = btn.innerHTML;
            
            navigator.clipboard.writeText(token).then(() => {
                btn.innerHTML = '<i class="fas fa-check"></i> Copied!';
                btn.style.background = '#10B981';
                
                setTimeout(() => {
                    btn.innerHTML = originalContent;
                    btn.style.background = '#111827';
                }, 2000);
            }).catch(() => {
                document.getElementById('token').style.display = 'block';
                alert('Please manually copy the token shown above');
            });
        }
    </script>
</body>
</html>
    `;
}

function renderErrorPage(message: string): string {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authentication Failed - ExportMyChat</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
            background: #f0f2f5;
            position: relative;
        }
        .background-pattern {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(135deg, #EF4444 0%, #DC2626 100%);
            z-index: -1;
        }
        .background-pattern::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.05'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
            opacity: 0.5;
        }
        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        .container {
            background: white;
            padding: 48px 40px;
            border-radius: 24px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.1);
            text-align: center;
            max-width: 480px;
            width: 100%;
            animation: slideUp 0.6s ease-out;
        }
        .logo {
            width: 88px;
            height: 88px;
            margin: 0 auto 24px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .logo img {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }
        .error-icon {
            width: 72px;
            height: 72px;
            margin: 0 auto 24px;
            border-radius: 50%;
            background: linear-gradient(135deg, #EF4444 0%, #DC2626 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 8px 16px -4px rgba(239, 68, 68, 0.3);
        }
        .error-icon i {
            color: white;
            font-size: 32px;
        }
        .subtitle {
            color: #6b7280;
            font-size: 0.85rem;
            margin-bottom: 10px;
        }
        .error-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: #fee2e2;
            color: #991b1b;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.875rem;
            font-weight: 600;
            margin-bottom: 25px;
        }
        .error-badge i {
            color: #EF4444;
        }
        .error-message {
            background: #fef2f2;
            border: 1px solid #fecaca;
            color: #991b1b;
            padding: 20px 24px;
            border-radius: 16px;
            margin: 14px 0;
            font-size: 0.95rem;
            line-height: 1.6;
        }
        .instructions {
            background: #f9fafb;
            padding: 20px 24px;
            border-radius: 16px;
            margin-top: 14px;
            border: 1px solid #e5e7eb;
            display: flex;
            flex-direction: column;
            align-items: flex-start;
            text-align: left;
            gap: 6px;
        }
        .instructions p {
            color: #4b5563;
            font-size: 0.9rem;
            line-height: 1.2;
        }
            
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            padding: 14px 28px;
            background: #111827;
            color: white;
            text-decoration: none;
            border-radius: 12px;
            font-weight: 600;
            font-size: 1rem;
            transition: all 0.25s ease;
            margin-top: 20px;
            border: none;
            cursor: pointer;
            font-family: 'Inter', sans-serif;
        }
        .btn:hover {
            background: #1f2937;
            transform: translateY(-2px);
            box-shadow: 0 8px 16px -4px rgba(0, 0, 0, 0.25);
        }
        .btn i {
            font-size: 16px;
        }
        .help-links {
            margin-top: 28px;
            padding-top: 24px;
            border-top: 1px solid #e5e7eb;
            display: flex;
            gap: 20px;
            justify-content: center;
            flex-wrap: wrap;
        }
        .help-links a {
            color: #6b7280;
            text-decoration: none;
            font-size: 0.875rem;
            font-weight: 500;
            transition: color 0.2s;
        }
        .help-links a:hover {
            color: #f59e0b;
        }
        .help-links a i {
            margin-right: 6px;
        }
        @media (max-width: 640px) {
            .container {
                padding: 36px 28px;
            }
            h1 {
                font-size: 1.75rem;
            }
            .help-links {
                flex-direction: column;
                gap: 12px;
            }
        }
    </style>
</head>
<body>
    <div class="background-pattern"></div>
    <div class="container">
        <div class="logo">
            <img src="/logo.png" alt="ExportMyChat" />
        </div>
        <div class="error-badge">
            <i class="fas fa-exclamation-circle"></i>
            <span>Authentication Error</span>
        </div>
        <p class="subtitle">We couldn't complete the authentication process</p>
        <div class="error-message">
            <i class="fas fa-info-circle" style="margin-right:8px;"></i>${message}
        </div>
        <div class="instructions">
            <p><strong>What to do next:</strong></p>
            <p>1. Close this window</p>
            <p>2. Return to the ExportMyChat extension</p>
            <p>3. Try the authentication process again</p>
        </div>
        <div class="help-links">
            <a href="https://github.com/kanhaiyadav/ExportMyChat" target="_blank">
                <i class="fab fa-github"></i> GitHub Repository
            </a>
            <a href="https://github.com/kanhaiyadav/ExportMyChat/issues" target="_blank">
                <i class="fas fa-bug"></i> Report Issue
            </a>
        </div>
    </div>
</body>
</html>
    `;
}

// ============================================
// Health Check & Start Server
// ============================================

app.get("/health", (_req: Request, res: Response) => {
    res.json({
        status: "ok",
        timestamp: new Date().toISOString(),
        sessions: sessions.size,
    });
});

app.listen(PORT, () => {
    console.log(`
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ExportMyChat Backend Server                                ║
║                                                              ║
║   Server running at: http://localhost:${PORT}                   ║
║   OAuth callback:    ${REDIRECT_URI}   ║
║                                                              ║
║   Configure this URL in Google Cloud Console:                ║
║   → APIs & Services → Credentials → OAuth 2.0 Client         ║
║   → Authorized redirect URIs                                 ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    `);
});
