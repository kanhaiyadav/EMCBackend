# ExportMyChat Backend Server

Backend server for Google Drive sync functionality. This solves the extension ID redirect URI problem by handling OAuth through a fixed backend URL.

## Why This Exists

Browser extensions have dynamically generated extension IDs, which creates problems with Google OAuth:

-   Chrome, Brave: Each unpacked extension gets a different ID
-   Edge Add-ons Store: Assigns a different ID than Chrome Web Store
-   Firefox: Uses `moz-extension://` with yet another ID format

By using a backend server, the OAuth redirect URL is fixed (e.g., `https://api.yoursite.com/oauth/callback`), and **the same redirect URI works for ALL browsers**.

## API Endpoints

### Authentication

| Endpoint          | Method | Description                            |
| ----------------- | ------ | -------------------------------------- |
| `/oauth/google`   | GET    | Starts OAuth flow, redirects to Google |
| `/oauth/callback` | GET    | OAuth callback, returns session token  |
| `/auth/status`    | GET    | Check if session is valid              |
| `/auth/signout`   | POST   | Invalidate session                     |

### Google Drive (requires `X-Session-Token` header)

| Endpoint                 | Method | Description              |
| ------------------------ | ------ | ------------------------ |
| `/drive/files`           | GET    | List files in app folder |
| `/drive/files/:fileName` | GET    | Download file content    |
| `/drive/files/:fileName` | PUT    | Upload/update file       |
| `/drive/files/:fileName` | DELETE | Delete a file            |
| `/drive/has-data`        | GET    | Check if any data exists |
| `/drive/all-data`        | DELETE | Delete all app data      |

### Health Check

| Endpoint  | Method | Description          |
| --------- | ------ | -------------------- |
| `/health` | GET    | Server health status |