# Websocket Proxy

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.22.0+-00ADD8?logo=go)](https://golang.org/)
[![Version](https://img.shields.io/badge/version-v1.2--Stable-blue)](https://github.com/risqinf/websocket-proxy/releases)

A high-performance, feature-rich WebSocket-to-TCP proxy server with real-time SSH session tracking, user authentication monitoring, and comprehensive REST API.

## Features

### Core Functionality
- WebSocket-to-TCP Tunneling - Seamlessly bridge WebSocket clients to TCP services
- Password Authentication - Optional security via custom headers
- Dynamic Target Routing - Override destinations with X-Real-Host header
- Real-time Bandwidth Monitoring - Track TX/RX per session
- High Performance - Concurrent connection handling with goroutines

### Session Management (v1.2+)
- User Detection - Automatic SSH username extraction from auth logs
- Multi-Server Support - Dropbear and OpenSSH compatible
- Session Tracking - Unique IDs, numbering, and PID correlation
- Duration Monitoring - Track connection uptime
- Session History - Per-user statistics and aggregation

### REST API (v1.2+)
- HTTP API Server - JSON endpoints for monitoring
- Real-time Stats - Server status, sessions, users, bandwidth
- CORS Enabled - Easy integration with web dashboards
- Session Analytics - Per-user and global statistics

### Additional Services
- UDPGW (BadVPN) - Built-in VPN multiplexer on port 7300
- Flexible Logging - Console + file output with color-coded levels
- Graceful Shutdown - Clean connection termination with summaries
- Cross-platform - Optimized for Linux (Debian 11+, Ubuntu 22.04+)

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [API Documentation](#api-documentation)
- [Architecture](#architecture)
- [Examples](#examples)
- [Performance](#performance)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)

## Installation

### Prerequisites

- **Go**: 1.22.0 or higher
- **OS**: Linux (Debian 11+, Ubuntu 22.04+)
- **SSH Server**: Dropbear or OpenSSH
- **Permissions**: Read access to `/var/log/auth.log`

### Build from Source

```bash
# Clone the repository
git clone https://github.com/risqinf/websocket-proxy.git
cd websocket-proxy

# Initialize Go module
go mod init ssh-ws

# Download dependencies
go mod tidy

# Build optimized binary
CGO_ENABLED=0 go build -ldflags "-s -w -X 'main.Credits=Risqi Nur Fadhilah' -X 'main.Version=v1.2-Stable'" -o ssh-ws

# Make executable
chmod +x ssh-ws
```

### Quick Install Script

```bash
# Download and install in one command
curl -fsSL https://raw.githubusercontent.com/risqinf/websocket-proxy/main/install.sh | bash
```

## Quick Start

### Basic Usage

```bash
# Start with defaults (port 8080, API on 8081)
./ssh-ws

# Custom configuration
./ssh-ws -p 9000 -api-port 9001 -t 127.0.0.1:22 -a myPassword
```

### Test Connection

```bash
# Terminal 1: Start server
./ssh-ws -p 8080 -a testpass

# Terminal 2: Test with curl
curl -i -N \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "X-Pass: testpass" \
  -H "X-Real-Host: 127.0.0.1:22" \
  http://localhost:8080/

# Terminal 3: Check API
curl http://localhost:8081/api/status
```

## Configuration

### Command-line Flags

| Flag | Description | Default | Example |
|------|-------------|---------|---------|
| `-p`, `--port` | WebSocket server port | `8080` | `-p 9000` |
| `-b`, `--bind` | Bind IP address | `0.0.0.0` | `-b 192.168.1.100` |
| `-t`, `--target` | Fallback SSH target | `127.0.0.1:22` | `-t 10.0.0.5:2222` |
| `-a`, `--auth` | Authentication password | (none) | `-a MySecretPass` |
| `-l`, `--log`, `--logs` | Log file path | (console only) | `-l /var/log/ssh-ws.log` |
| `--auth-log` | SSH auth log path | `/var/log/auth.log` | `--auth-log /custom/auth.log` |
| `--api-port` | HTTP API port (0=disable) | `8081` | `--api-port 9001` |

### Configuration Examples

#### Example 1: Basic SSH Proxy
```bash
./ssh-ws -p 8080 -t 127.0.0.1:22
```
Simple WebSocket tunneling to local SSH server.

#### Example 2: Secure Production Setup
```bash
./ssh-ws \
  -b 0.0.0.0 \
  -p 8080 \
  -t 127.0.0.1:22 \
  -a "$(cat /etc/ssh-ws/password)" \
  -l /var/log/ssh-ws/proxy.log \
  --auth-log /var/log/auth.log \
  --api-port 8081
```
Full-featured production configuration with authentication, logging, and API.

#### Example 3: Multi-Host Proxy
```bash
./ssh-ws -p 8080 -t fallback.server.com:22
```
Clients can override target using `X-Real-Host` header.

#### Example 4: API Disabled
```bash
./ssh-ws -p 8080 --api-port 0
```
Run without HTTP API (monitoring disabled).

## API Documentation

### Base URL
```
http://<server-ip>:8081
```

### Quick Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | Server uptime and session counts |
| `/api/sessions` | GET | All sessions + user statistics |
| `/api/sessions/active` | GET | Currently active sessions |
| `/api/users` | GET | Per-user bandwidth statistics |
| `/api/stats` | GET | Global server statistics |
| `/health` | GET | Health check |

### Example Responses

**GET /api/status**
```json
{
  "success": true,
  "data": {
    "version": "v1.2-Stable",
    "uptime": "2h30m15s",
    "total_sessions": 156,
    "active_sessions": 12
  }
}
```

**GET /api/sessions/active**
```json
{
  "success": true,
  "data": {
    "count": 3,
    "sessions": [
      {
        "id": "0042-a3f5c1",
        "real_client_ip": "203.0.113.45",
        "username": "john",
        "session_number": 2,
        "duration": "15m30s",
        "tx_formatted": "1.0 MB",
        "rx_formatted": "2.0 MB"
      }
    ]
  }
}
```

**Full API Documentation**: See [API_DOCUMENTATION.md](API_DOCUMENTATION.md)

## Architecture

### Request Flow

```
┌─────────┐                 ┌──────────────┐                 ┌─────────┐
│ Client  │───WebSocket────>│  GO-TUNNEL   │────TCP─────────>│   SSH   │
│         │<────Tunnel─────>│     PRO      │<───Session─────>│ Server  │
└─────────┘                 └──────┬───────┘                 └─────────┘
                                   │
                                   │ Monitors
                                   ▼
                            ┌──────────────┐
                            │ /var/log/    │
                            │  auth.log    │
                            └──────┬───────┘
                                   │ Extracts
                                   ▼
                            ┌──────────────┐
                            │  Username +  │
                            │     PID      │
                            └──────────────┘
```

### Components

1. **WebSocket Handler** - Accepts connections, validates auth, establishes tunnels
2. **Auth Log Monitor** - Tails `/var/log/auth.log` for SSH login events
3. **Session Manager** - Tracks active sessions with `sync.Map`
4. **Bandwidth Monitor** - Real-time TX/RX tracking per session
5. **HTTP API Server** - RESTful endpoints for monitoring
6. **UDPGW Service** - BadVPN multiplexer for VPN support

### Session Tracking

```
Connection → Session ID (0042-a3f5c1)
    ↓
Proxy Port (54321) ← Mapped to Session
    ↓
Auth Log: "Accepted password for john from IP port 54321"
    ↓
Extract: Username (john), PID (12345)
    ↓
Update Session: john-2 (PID:12345) [dropbear]
```

**Technical Details**: See [CODE_DOCUMENTATION.md](CODE_DOCUMENTATION.md)

## Examples

### Client Connection (JavaScript)

```javascript
const ws = new WebSocket('ws://localhost:8080/', {
  headers: {
    'X-Pass': 'myPassword',
    'X-Real-Host': '192.168.1.100:22'
  }
});

ws.onopen = () => console.log('Connected to SSH proxy');
ws.onmessage = (event) => console.log('Received:', event.data);
```

### Monitoring Dashboard (Python)

```python
import requests
import time

API_BASE = "http://localhost:8081"

while True:
    resp = requests.get(f"{API_BASE}/api/stats")
    data = resp.json()['data']
    
    print(f"Active: {data['active_sessions']} | "
          f"Bandwidth: {data['total_formatted']}")
    
    time.sleep(5)
```

### Custom Headers

```http
GET / HTTP/1.1
Host: proxy.example.com
Upgrade: websocket
Connection: Upgrade
X-Real-Host: internal-server.local:22
X-Pass: mySecretPassword
```

## Performance

### Benchmarks

- **Latency Overhead**: ~1-2ms additional per request
- **Throughput**: Limited by network bandwidth, not CPU
- **Concurrent Connections**: Tested with 1000+ simultaneous sessions
- **Memory Usage**: ~10MB base + ~1-2KB per active session
- **CPU Usage**: <5% on 4-core system with 100 active sessions

### Optimizations

- **sync.Map** for lock-free concurrent session access
- **Atomic operations** for bandwidth counters (zero-copy)
- **Goroutine pooling** via Go runtime
- **Efficient regex compilation** (compiled once, reused)
- **Zero-copy proxying** with `io.Copy`

## Security

### Best Practices

1. **Always Use Authentication**
   ```bash
   ./ssh-ws -a "$(openssl rand -base64 32)"
   ```

2. **Bind to Specific IP**
   ```bash
   ./ssh-ws -b 192.168.1.100  # Don't expose to 0.0.0.0 in production
   ```

3. **Firewall Rules**
   ```bash
   # Allow only specific IPs
   iptables -A INPUT -p tcp --dport 8080 -s 203.0.113.0/24 -j ACCEPT
   iptables -A INPUT -p tcp --dport 8080 -j DROP
   ```

4. **Use Reverse Proxy with TLS**
   ```nginx
   server {
       listen 443 ssl;
       server_name tunnel.example.com;
       
       ssl_certificate /path/to/cert.pem;
       ssl_certificate_key /path/to/key.pem;
       
       location / {
           proxy_pass http://127.0.0.1:8080;
           proxy_http_version 1.1;
           proxy_set_header Upgrade $http_upgrade;
           proxy_set_header Connection "upgrade";
       }
   }
   ```

5. **Monitor Logs**
   ```bash
   tail -f /var/log/ssh-ws.log | grep -E 'AUTH|ERROR'
   ```

6. **Restrict Auth Log Access**
   ```bash
   # Add user to adm group for auth.log access
   usermod -aG adm ssh-ws-user
   ```

### Security Considerations

- **API Security**: Current version has no API authentication (add in production)
- **Password Storage**: Use environment variables, not command-line args
- **Rate Limiting**: Not implemented (add per-IP limits for production)
- **Input Validation**: All regex inputs are validated and sanitized

## Docker Support (Coming Soon)

```dockerfile
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o ssh-ws

FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/ssh-ws /usr/local/bin/
EXPOSE 8080 8081 7300
ENTRYPOINT ["ssh-ws"]
```

## Systemd Service

Create `/etc/systemd/system/ssh-ws.service`:

```ini
[Unit]
Description=GO-TUNNEL PRO WebSocket Proxy
After=network.target

[Service]
Type=simple
User=ssh-ws
Group=ssh-ws
WorkingDirectory=/opt/ssh-ws
Environment="PASSWORD_FILE=/etc/ssh-ws/password"
ExecStart=/usr/local/bin/ssh-ws \
  -p 8080 \
  -t 127.0.0.1:22 \
  -a "$(cat ${PASSWORD_FILE})" \
  -l /var/log/ssh-ws/proxy.log \
  --api-port 8081
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable ssh-ws
sudo systemctl start ssh-ws
sudo systemctl status ssh-ws
```

## Monitoring

### Log Levels

```
[INFO]    - General information
[CONN]    - New connections
[AUTH]    - Authentication events
[MONITOR] - Bandwidth updates
[END]     - Connection closures
[!]       - Warnings
[-]       - Errors
```

### Real-time Monitoring

```bash
# Watch active sessions
watch -n 2 'curl -s http://localhost:8081/api/sessions/active | jq ".data.count"'

# Monitor bandwidth
while true; do
  curl -s http://localhost:8081/api/stats | jq '.data | "\(.active_sessions) sessions | \(.total_formatted)"'
  sleep 5
done

# Tail logs with color
tail -f /var/log/ssh-ws.log | ccze -A
```

## Troubleshooting

### Common Issues

**Issue**: Username shows "detecting..."
```bash
# Check auth log permissions
ls -la /var/log/auth.log

# Verify SSH server is logging
tail -f /var/log/auth.log | grep -E 'dropbear|sshd'

# Add user to adm group
sudo usermod -aG adm $USER
```

**Issue**: API not responding
```bash
# Check if API is enabled
curl http://localhost:8081/health

# Verify port binding
netstat -tlnp | grep 8081

# Check logs
tail -f /var/log/ssh-ws.log | grep API
```

**Issue**: Connection refused
```bash
# Verify SSH server is running
systemctl status ssh  # or dropbear

# Test direct SSH connection
ssh localhost -p 22

# Check firewall
iptables -L -n | grep 22
```

**Issue**: High memory usage
```bash
# Check session count
curl http://localhost:8081/api/status

# Monitor goroutines
curl http://localhost:8081/debug/pprof/goroutine?debug=1
```

## Documentation

- [CHANGELOG.md](CHANGELOG.md) - Version history and migration guides
- [CODE_DOCUMENTATION.md](CODE_DOCUMENTATION.md) - Technical architecture and implementation details
- [API_DOCUMENTATION.md](API_DOCUMENTATION.md) - Complete REST API reference
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 Risqi Nur Fadhilah

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

## Contributors

<a href="https://github.com/risqinf/websocket-proxy/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=risqinf/websocket-proxy" />
</a>

## Support

- **Issues**: [GitHub Issues](https://github.com/risqinf/websocket-proxy/issues)
- **Telegram**: [@risqinf](https://t.me/risqinf)
- **Email**: Contact via GitHub profile
- **Discussions**: [GitHub Discussions](https://github.com/risqinf/websocket-proxy/discussions)
- **Telegram Channel**: [system.notes.labs](https://t.me/systems_notes)

## Acknowledgments

- **Developer**: Risqi Nur Fadhilah ([@risqinf](https://github.com/risqinf))
- **Tester**: Rerechan02
- **UDPGW Library**: [mukswilly/udpgw](https://github.com/mukswilly/udpgw)
- **Community**: All contributors and testers

## Statistics

![GitHub stars](https://img.shields.io/github/stars/risqinf/websocket-proxy?style=social)
![GitHub forks](https://img.shields.io/github/forks/risqinf/websocket-proxy?style=social)
![GitHub issues](https://img.shields.io/github/issues/risqinf/websocket-proxy)
![GitHub pull requests](https://img.shields.io/github/issues-pr/risqinf/websocket-proxy)

---

<p align="center">
  <b>Made with care by Risqi Nur Fadhilah</b><br>
  <sub>If this project helped you, please give it a star</sub>
</p>

<p align="center">
  <a href="#top">Back to Top</a>
</p>
