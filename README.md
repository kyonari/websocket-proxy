# Websocket Proxy

A lightweight, high-performance WebSocket-to-TCP proxy server written in Go. This tool enables WebSocket clients to connect to TCP services (like SSH) through a WebSocket tunnel.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.22.0+-00ADD8?logo=go)](https://golang.org/)

## Features

- WebSocket-to-TCP tunneling
- Optional password authentication
- Real-time bandwidth monitoring (TX/RX)
- Flexible logging (console + file)
- Custom target routing via headers
- Lightweight and fast
- Automatic fallback target
- Cross-platform support

## Installation

### Prerequisites

- Go 1.22.0 or higher
- Linux (Debian 11+ or Ubuntu 22.04+)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/risqinf/websocket-proxy.git
cd websocket-proxy

# Build the binary
CGO_ENABLED=0 go build -ldflags "-s -w -X 'main.Credits=Risqi Nur Fadhilah' -X 'main.Version=v1.0-Stable'" -o ssh-ws

# Make it executable
chmod +x ssh-ws
```

## Usage

### Basic Usage

```bash
# Start server with defaults (port 8080, bind to all interfaces)
./ssh-ws

# Specify custom port
./ssh-ws -p 9000

# Bind to specific IP
./ssh-ws -b 192.168.1.100 -p 8080

# Set fallback target
./ssh-ws -t 127.0.0.1:22

# Enable authentication
./ssh-ws -a mySecretPassword

# Enable file logging
./ssh-ws -l /var/log/ssh-ws.log

# Combine multiple options
./ssh-ws -p 9000 -b 0.0.0.0 -t 127.0.0.1:22 -a myPassword -l ./logs/proxy.log
```

### Command-line Flags

| Flag | Long Flag | Description | Default |
|------|-----------|-------------|---------|
| `-p` | `--port` | Server port | `8080` |
| `-b` | `--bind` | Bind IP address | `0.0.0.0` |
| `-t` | `--target` | Fallback target (IP:Port) | `127.0.0.1:22` |
| `-a` | `--auth` | Authentication password | (none) |
| `-l` | `--logs` | Log file path | (none) |
| `-h` | `--help` | Show help message | - |

## How It Works

### Request Flow

```
Client (WebSocket) → Proxy Server → Target Service (TCP)
                      ↓
                  Authentication (optional)
                      ↓
                  Target Resolution
                      ↓
                  WebSocket Upgrade
                      ↓
                  Bidirectional Tunnel
```

### Custom Headers

The proxy supports custom HTTP headers for routing and authentication:

- **`X-Real-Host`**: Specify target host (e.g., `example.com:443`)
- **`X-Pass`**: Authentication password (if enabled)

### Example Client Request

```http
GET / HTTP/1.1
Host: proxy-server.com
Upgrade: websocket
Connection: Upgrade
X-Real-Host: internal-server.local:22
X-Pass: mySecretPassword
```

## Configuration Examples

### Example 1: Basic SSH Proxy

```bash
./ssh-ws -p 8080 -t 127.0.0.1:22
```

Tunnels WebSocket connections to local SSH server.

### Example 2: Secure Proxy with Authentication

```bash
./ssh-ws -p 9000 -a "MyStr0ngP@ssw0rd" -l /var/log/ssh-ws.log
```

Requires password authentication and logs all activity.

### Example 3: Multi-Host Proxy

```bash
./ssh-ws -p 8080 -t 127.0.0.1:443
```

Clients can override target using `X-Real-Host` header.

### Example 4: Production Setup

```bash
./ssh-ws \
  -b 0.0.0.0 \
  -p 8080 \
  -t 127.0.0.1:22 \
  -a "$(cat /etc/ssh-ws/password)" \
  -l /var/log/ssh-ws/proxy.log
```

## Monitoring

The proxy provides real-time connection monitoring:

```
[STATUS] example.com:443 | TX: 1.2 MB | RX: 3.4 MB
[=] Closed: example.com:443 | TX: 5.6 MB | RX: 10.1 MB
```

- **TX**: Data transmitted (client → target)
- **RX**: Data received (target → client)
- Updates every 10 seconds for active connections

## Log Output

### Log Format

```
2025/01/07 10:30:45 [*] Server berjalan di: 0.0.0.0:8080
2025/01/07 10:30:50 [+] Tunnel: 192.168.1.100:54321 -> example.com:443
2025/01/07 10:31:00 [STATUS] example.com:443 | TX: 128.5 KB | RX: 256.3 KB
2025/01/07 10:31:15 [=] Closed: example.com:443 | TX: 512.1 KB | RX: 1.2 MB
2025/01/07 10:31:20 [!] Auth Gagal dari 192.168.1.200:12345
```

### Log Levels

- `[*]` Info: General information
- `[+]` Success: Successful connections
- `[!]` Warning: Authentication failures
- `[-]` Error: Connection errors
- `[STATUS]` Status: Bandwidth monitoring
- `[=]` Close: Connection closed

## Security Considerations

1. **Authentication**: Always use `-a` flag in production
2. **Binding**: Bind to specific IP (`-b`) instead of `0.0.0.0` when possible
3. **Firewall**: Configure firewall rules to restrict access
4. **Logs**: Monitor logs regularly for suspicious activity
5. **HTTPS**: Consider using reverse proxy (nginx/caddy) with SSL

## Systemd Service (Optional)

Create `/etc/systemd/system/ssh-ws.service`:

```ini
[Unit]
Description=SSH WebSocket Proxy
After=network.target

[Service]
Type=simple
User=nobody
ExecStart=/usr/local/bin/ssh-ws -p 8080 -t 127.0.0.1:22 -a yourPassword -l /var/log/ssh-ws.log
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

## Troubleshooting

### Connection Refused

```
[-] Gagal connect ke target:22: connection refused
```

**Solution**: Ensure target service is running and accessible.

### Authentication Failed

```
[!] Auth Gagal dari 192.168.1.100:54321
```

**Solution**: Check `X-Pass` header matches server password.

### Port Already in Use

```
[-] Gagal memulai server: address already in use
```

**Solution**: Use different port with `-p` flag or stop conflicting service.

## Performance

- **Latency**: Minimal overhead (~1-2ms)
- **Throughput**: Limited by network bandwidth
- **Connections**: Handles thousands of concurrent connections
- **Memory**: ~5-10MB base + ~1KB per connection

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Credits

- **Developer**: Risqi Nur Fadhilah
- **Tester**: Rerechan02
- **Telegram**: [@risqinf](https://t.me/risqinf)
- **GitHub**: [@risqinf](https://github.com/risqinf)

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## Support

- **Issues**: [GitHub Issues](https://github.com/risqinf/websocket-proxy/issues)
- **Telegram**: [@risqinf](https://t.me/risqinf)
- **Email**: Contact via GitHub profile

## Changelog

### v1.0.1 (Current)
- Initial stable release
- WebSocket tunneling support
- Authentication mechanism
- Bandwidth monitoring
- File logging

---

**Made with ❤️ by Risqi Nur Fadhilah**
