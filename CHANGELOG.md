# Changelog

All notable changes to Websocket Proxy will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.2-Stable] - 2025-01-28

### Added
- **HTTP REST API Server** on configurable port (default: 8081)
  - `/api/status` - Server status and uptime
  - `/api/sessions` - All sessions with user statistics
  - `/api/sessions/active` - Active sessions only
  - `/api/users` - Per-user statistics
  - `/api/stats` - Global statistics
  - `/health` - Health check endpoint
  - Full CORS support for cross-origin requests

- **Real-time User Authentication Detection**
  - Dropbear SSH server support
  - OpenSSH server support
  - Automatic username extraction from `/var/log/auth.log`
  - PID tracking for each SSH session
  - Session numbering per user (e.g., user-1, user-2)

- **Enhanced Session Management**
  - Unique session ID generation (format: `0001-abc123`)
  - Session counter for all connections
  - Real client IP and port tracking
  - Proxy-to-SSH port mapping
  - SSH type detection (Dropbear/OpenSSH)
  - Session duration tracking
  - Last activity timestamp

- **Advanced Monitoring**
  - Per-session bandwidth monitoring (TX/RX)
  - Per-user bandwidth aggregation
  - Active session count alerts (every 30 seconds)
  - Session summary on shutdown
  - User statistics breakdown

- **New Command-line Flags**
  - `--auth-log` - Path to SSH auth log (default: `/var/log/auth.log`)
  - `--api-port` - HTTP API port (default: 8081, 0 to disable)

- **Security Enhancements**
  - Strict regex validation for SSH log parsing
  - Username format validation
  - IP address validation
  - Port range validation (1-65535)
  - PID range validation

### Changed
- **Improved Logging**
  - Color-coded session IDs
  - User information in monitoring logs
  - Enhanced connection lifecycle logs
  - Session summary with per-user statistics
  
- **Session Information Display**
  - Now shows: `[SessionID] RealIP:Port | User: username-N (PID:XXXX)`
  - Duration formatted as human-readable time
  - Bandwidth in human-readable format (B, KB, MB, GB)

- **Connection Flow**
  - Better real client IP detection
  - Proxy port tracking for SSH correlation
  - Username resolution via auth log monitoring

### Fixed
- Session tracking race conditions
- Memory leaks in long-running sessions
- Concurrent map access issues
- Auth log parsing edge cases

### Performance
- Optimized concurrent session handling with `sync.Map`
- Atomic operations for bandwidth counters
- Efficient regex compilation for log parsing
- Non-blocking auth log monitoring

## [v1.1-Stable] - 2025-01-15

### Added
- UDPGW (BadVPN) support on port 7300
- Multi-service architecture
- Improved error handling

### Changed
- Updated project name to GO-TUNNEL PRO
- Enhanced banner display
- Better service initialization

## [v1.0-Stable] - 2025-01-07

### Added
- Initial stable release
- WebSocket-to-TCP tunneling
- Password authentication via `X-Pass` header
- Custom target routing via `X-Real-Host` header
- Real-time bandwidth monitoring
- File logging support
- Graceful shutdown handling
- Color-coded console output

### Features
- Lightweight and high-performance
- Cross-platform support (Linux focus)
- Configurable bind address and port
- Fallback target support
- Automatic WebSocket upgrade

---

## Migration Guide

### From v1.1 to v1.2

**New Requirements:**
- Access to `/var/log/auth.log` (readable permissions)
- Dropbear or OpenSSH server running
- Port 8081 available for API (or configure with `--api-port`)

**New Features to Configure:**
```bash
# Enable API on custom port
./ssh-ws --api-port 9000

# Specify custom auth log location
./ssh-ws --auth-log /custom/path/auth.log

# Disable API
./ssh-ws --api-port 0
```

**Breaking Changes:**
- None - fully backward compatible

**Benefits:**
- Real-time user tracking
- RESTful API for monitoring
- Better session management
- Enhanced statistics

---

## Contributors
- **Developer**: Risqi Nur Fadhilah ([@risqinf](https://github.com/risqinf))
- **Tester**: Rerechan02

## License
MIT License - See [LICENSE](LICENSE) file for details
