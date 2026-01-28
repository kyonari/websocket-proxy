# API Documentation

Websocket Proxy HTTP REST API Reference - v1.2-Stable

## Base URL

```
http://<server-ip>:<api-port>
```

Default: `http://localhost:8081`

## Authentication

**Current Version**: No authentication required

⚠️ **Production Warning**: Implement authentication before exposing to public networks.

## CORS Policy

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, OPTIONS
Access-Control-Allow-Headers: Content-Type
```

## Response Format

All endpoints return JSON in this structure:

```json
{
  "success": true,
  "message": "Optional message",
  "data": { /* endpoint-specific data */ }
}
```

## Endpoints

### 1. Server Status

Get server uptime and session statistics.

**Endpoint**: `GET /api/status`

**Response**:
```json
{
  "success": true,
  "data": {
    "version": "v1.2-Stable",
    "uptime": "2h30m15s",
    "uptime_seconds": 9015,
    "total_sessions": 156,
    "active_sessions": 12,
    "closed_sessions": 144
  }
}
```

**Fields**:
| Field | Type | Description |
|-------|------|-------------|
| `version` | string | Server version |
| `uptime` | string | Human-readable uptime |
| `uptime_seconds` | int | Uptime in seconds |
| `total_sessions` | int64 | Total sessions since start |
| `active_sessions` | int | Currently active sessions |
| `closed_sessions` | int64 | Total closed sessions |

**Example**:
```bash
curl http://localhost:8081/api/status
```

---

### 2. All Sessions

Get all active sessions with detailed information and user statistics.

**Endpoint**: `GET /api/sessions`

**Response**:
```json
{
  "success": true,
  "data": {
    "total_sessions": 156,
    "active_sessions": 3,
    "closed_sessions": 153,
    "sessions": [
      {
        "id": "0042-a3f5c1",
        "real_client_ip": "203.0.113.45",
        "real_client_port": "54321",
        "username": "john",
        "session_number": 2,
        "pid": 12345,
        "ssh_type": "dropbear",
        "start_time": "2025-01-28T10:30:45Z",
        "tx_bytes": 1048576,
        "rx_bytes": 2097152,
        "duration": "15m30s",
        "tx_formatted": "1.0 MB",
        "rx_formatted": "2.0 MB",
        "total_formatted": "3.0 MB"
      }
    ],
    "user_stats": {
      "john": {
        "username": "john",
        "session_count": 2,
        "total_tx": 2097152,
        "total_rx": 4194304,
        "total_bytes": 6291456,
        "tx_formatted": "2.0 MB",
        "rx_formatted": "4.0 MB",
        "total_formatted": "6.0 MB"
      }
    }
  }
}
```

**Session Fields**:
| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique session identifier |
| `real_client_ip` | string | Client's actual IP address |
| `real_client_port` | string | Client's source port |
| `username` | string | SSH username (or "detecting...") |
| `session_number` | int | User's session number (e.g., 2 = john-2) |
| `pid` | int | SSH daemon process ID |
| `ssh_type` | string | "dropbear", "openssh", or "unknown" |
| `start_time` | string (ISO8601) | Session start timestamp |
| `tx_bytes` | int64 | Bytes transmitted (client → server) |
| `rx_bytes` | int64 | Bytes received (server → client) |
| `duration` | string | Session duration |
| `tx_formatted` | string | Human-readable TX size |
| `rx_formatted` | string | Human-readable RX size |
| `total_formatted` | string | Total bandwidth used |

**User Stats Fields**:
| Field | Type | Description |
|-------|------|-------------|
| `username` | string | SSH username |
| `session_count` | int | Number of active sessions |
| `total_tx` | int64 | Aggregate TX across all sessions |
| `total_rx` | int64 | Aggregate RX across all sessions |
| `total_bytes` | int64 | Total bandwidth across all sessions |
| `tx_formatted` | string | Human-readable total TX |
| `rx_formatted` | string | Human-readable total RX |
| `total_formatted` | string | Human-readable total bandwidth |

**Example**:
```bash
curl http://localhost:8081/api/sessions
```

**Use Cases**:
- Dashboard overview
- User activity monitoring
- Session history analysis

---

### 3. Active Sessions (Simplified)

Get list of currently active sessions with minimal information.

**Endpoint**: `GET /api/sessions/active`

**Response**:
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
        "pid": 12345,
        "ssh_type": "dropbear",
        "duration": "15m30s",
        "tx_formatted": "1.0 MB",
        "rx_formatted": "2.0 MB",
        "total_formatted": "3.0 MB"
      }
    ]
  }
}
```

**Example**:
```bash
curl http://localhost:8081/api/sessions/active
```

**Use Cases**:
- Quick session count check
- Real-time monitoring displays
- Lightweight polling

---

### 4. User Statistics

Get per-user bandwidth and session statistics.

**Endpoint**: `GET /api/users`

**Response**:
```json
{
  "success": true,
  "data": {
    "count": 5,
    "users": [
      {
        "username": "john",
        "session_count": 2,
        "total_tx": 2097152,
        "total_rx": 4194304,
        "total_bytes": 6291456,
        "tx_formatted": "2.0 MB",
        "rx_formatted": "4.0 MB",
        "total_formatted": "6.0 MB"
      },
      {
        "username": "alice",
        "session_count": 1,
        "total_tx": 1048576,
        "total_rx": 524288,
        "total_bytes": 1572864,
        "tx_formatted": "1.0 MB",
        "rx_formatted": "512.0 KB",
        "total_formatted": "1.5 MB"
      }
    ]
  }
}
```

**Example**:
```bash
curl http://localhost:8081/api/users
```

**Use Cases**:
- User quota monitoring
- Bandwidth billing
- User activity reports

---

### 5. Global Statistics

Get aggregate server statistics including total bandwidth.

**Endpoint**: `GET /api/stats`

**Response**:
```json
{
  "success": true,
  "data": {
    "uptime": "2h30m15s",
    "uptime_seconds": 9015,
    "total_sessions": 156,
    "active_sessions": 12,
    "closed_sessions": 144,
    "total_tx": 104857600,
    "total_rx": 209715200,
    "total_bytes": 314572800,
    "tx_formatted": "100.0 MB",
    "rx_formatted": "200.0 MB",
    "total_formatted": "300.0 MB",
    "unique_users": 8,
    "users_breakdown": {
      "john": 2,
      "alice": 3,
      "bob": 1
    }
  }
}
```

**Fields**:
| Field | Type | Description |
|-------|------|-------------|
| `uptime` | string | Server uptime (human-readable) |
| `uptime_seconds` | int | Server uptime in seconds |
| `total_sessions` | int64 | All sessions since start |
| `active_sessions` | int | Currently active sessions |
| `closed_sessions` | int64 | Completed sessions |
| `total_tx` | int64 | Aggregate TX (all sessions) |
| `total_rx` | int64 | Aggregate RX (all sessions) |
| `total_bytes` | int64 | Total bandwidth usage |
| `tx_formatted` | string | Human-readable TX |
| `rx_formatted` | string | Human-readable RX |
| `total_formatted` | string | Human-readable total |
| `unique_users` | int | Number of unique users |
| `users_breakdown` | object | Session count per user |

**Example**:
```bash
curl http://localhost:8081/api/stats
```

**Use Cases**:
- Server performance monitoring
- Capacity planning
- Billing reports

---

### 6. Health Check

Simple endpoint to verify API is running.

**Endpoint**: `GET /health`

**Response**:
```json
{
  "success": true,
  "message": "OK"
}
```

**Example**:
```bash
curl http://localhost:8081/health
```

**Use Cases**:
- Load balancer health checks
- Monitoring systems (Nagios, Prometheus)
- Uptime checks

---

## Error Responses

All errors return appropriate HTTP status codes with JSON:

```json
{
  "success": false,
  "message": "Error description"
}
```

**Common Status Codes**:
| Code | Meaning |
|------|---------|
| 200 | Success |
| 400 | Bad Request |
| 404 | Endpoint Not Found |
| 500 | Internal Server Error |

---

## Rate Limiting

**Current**: No rate limiting implemented

**Recommendations**:
- Implement per-IP rate limiting
- Typical limit: 100 requests/minute per IP
- Return HTTP 429 (Too Many Requests) when exceeded

---

## Integration Examples

### JavaScript (Fetch API)

```javascript
// Get server status
async function getStatus() {
  const response = await fetch('http://localhost:8081/api/status');
  const data = await response.json();
  console.log(`Active sessions: ${data.data.active_sessions}`);
}

// Get active sessions
async function getActiveSessions() {
  const response = await fetch('http://localhost:8081/api/sessions/active');
  const data = await response.json();
  
  data.data.sessions.forEach(session => {
    console.log(`${session.username}: ${session.total_formatted}`);
  });
}

// Poll for updates every 5 seconds
setInterval(getActiveSessions, 5000);
```

### Python (Requests)

```python
import requests
import time

API_BASE = "http://localhost:8081"

def get_user_stats():
    response = requests.get(f"{API_BASE}/api/users")
    data = response.json()
    
    for user in data['data']['users']:
        print(f"{user['username']}: {user['session_count']} sessions, "
              f"{user['total_formatted']} total")

def monitor_bandwidth():
    while True:
        response = requests.get(f"{API_BASE}/api/stats")
        data = response.json()['data']
        
        print(f"Total: {data['total_formatted']} "
              f"({data['active_sessions']} active)")
        
        time.sleep(10)

if __name__ == "__main__":
    monitor_bandwidth()
```

### Bash (cURL)

```bash
#!/bin/bash

API_BASE="http://localhost:8081"

# Get active session count
get_active_count() {
  curl -s "$API_BASE/api/status" | jq -r '.data.active_sessions'
}

# Get total bandwidth
get_total_bandwidth() {
  curl -s "$API_BASE/api/stats" | jq -r '.data.total_formatted'
}

# Monitor loop
while true; do
  ACTIVE=$(get_active_count)
  BANDWIDTH=$(get_total_bandwidth)
  echo "[$(date '+%H:%M:%S')] Active: $ACTIVE | Bandwidth: $BANDWIDTH"
  sleep 5
done
```

### Go (Native HTTP Client)

```go
package main

import (
    "encoding/json"
    "fmt"
    "net/http"
    "time"
)

type APIResponse struct {
    Success bool                   `json:"success"`
    Data    map[string]interface{} `json:"data"`
}

func getStats() (*APIResponse, error) {
    resp, err := http.Get("http://localhost:8081/api/stats")
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var apiResp APIResponse
    if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
        return nil, err
    }
    
    return &apiResp, nil
}

func main() {
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()
    
    for range ticker.C {
        stats, err := getStats()
        if err != nil {
            fmt.Printf("Error: %v\n", err)
            continue
        }
        
        fmt.Printf("Active: %.0f | Total: %s\n",
            stats.Data["active_sessions"],
            stats.Data["total_formatted"])
    }
}
```

---

## WebSocket Alternative (Future)

For real-time updates, consider WebSocket endpoint:

```javascript
// Future feature (not implemented in v1.2)
const ws = new WebSocket('ws://localhost:8081/ws/sessions');

ws.onmessage = (event) => {
  const session = JSON.parse(event.data);
  console.log(`New session: ${session.username}`);
};
```

---

## Prometheus Metrics (Future)

Example Prometheus exporter format:

```
# HELP ssh_ws_active_sessions Number of active sessions
# TYPE ssh_ws_active_sessions gauge
ssh_ws_active_sessions 12

# HELP ssh_ws_total_sessions Total sessions since start
# TYPE ssh_ws_total_sessions counter
ssh_ws_total_sessions 156

# HELP ssh_ws_bandwidth_bytes Total bandwidth in bytes
# TYPE ssh_ws_bandwidth_bytes counter
ssh_ws_bandwidth_bytes{direction="tx"} 104857600
ssh_ws_bandwidth_bytes{direction="rx"} 209715200
```

---

## Security Best Practices

### 1. API Key Authentication

Add API key header to all requests:

```javascript
fetch('http://localhost:8081/api/sessions', {
  headers: {
    'X-API-Key': 'your-secret-api-key'
  }
});
```

Server-side validation:
```go
func apiKeyMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        apiKey := r.Header.Get("X-API-Key")
        if apiKey != os.Getenv("API_KEY") {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }
        next(w, r)
    }
}
```

### 2. HTTPS Only

Use reverse proxy (nginx/caddy) for TLS:

```nginx
server {
    listen 443 ssl;
    server_name api.example.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location /api/ {
        proxy_pass http://localhost:8081;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 3. Rate Limiting

Implement per-IP rate limiting:

```go
import "golang.org/x/time/rate"

var limiters = make(map[string]*rate.Limiter)

func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        ip := getClientIP(r)
        limiter := getLimiter(ip)
        
        if !limiter.Allow() {
            http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
            return
        }
        next(w, r)
    }
}
```

### 4. CORS Restrictions

Restrict to specific domains:

```go
w.Header().Set("Access-Control-Allow-Origin", "https://dashboard.example.com")
```

---

## Monitoring Dashboard Example

### HTML + JavaScript Dashboard

```html
<!DOCTYPE html>
<html>
<head>
    <title>Websocket Proxy Dashboard</title>
    <style>
        body { font-family: monospace; background: #1a1a1a; color: #0f0; padding: 20px; }
        .stat { background: #000; border: 1px solid #0f0; padding: 15px; margin: 10px 0; }
        .session { background: #111; padding: 10px; margin: 5px 0; border-left: 3px solid #0f0; }
    </style>
</head>
<body>
    <h1>Websocket Proxy Dashboard</h1>
    
    <div class="stat" id="status">Loading...</div>
    
    <h2>Active Sessions</h2>
    <div id="sessions">Loading...</div>
    
    <script>
        const API = 'http://localhost:8081';
        
        async function updateStats() {
            const resp = await fetch(`${API}/api/stats`);
            const data = await resp.json();
            const d = data.data;
            
            document.getElementById('status').innerHTML = `
                <strong>Uptime:</strong> ${d.uptime} |
                <strong>Active:</strong> ${d.active_sessions} |
                <strong>Total:</strong> ${d.total_formatted}
            `;
        }
        
        async function updateSessions() {
            const resp = await fetch(`${API}/api/sessions/active`);
            const data = await resp.json();
            
            const html = data.data.sessions.map(s => `
                <div class="session">
                    <strong>${s.username}-${s.session_number}</strong> 
                    [${s.real_client_ip}] - 
                    ${s.duration} - 
                    ↑${s.tx_formatted} ↓${s.rx_formatted}
                </div>
            `).join('');
            
            document.getElementById('sessions').innerHTML = html || 'No active sessions';
        }
        
        setInterval(() => {
            updateStats();
            updateSessions();
        }, 2000);
        
        updateStats();
        updateSessions();
    </script>
</body>
</html>
```

---

## Troubleshooting

### API Not Responding

```bash
# Check if API is enabled
curl http://localhost:8081/health

# Check server logs
tail -f /var/log/ssh-ws.log | grep API

# Verify port is open
netstat -tlnp | grep 8081
```

### CORS Errors in Browser

```javascript
// If you see CORS errors, check:
// 1. API server CORS headers
// 2. Browser console for specific error
// 3. Try curl to verify API works

// Workaround: Use proxy
// In package.json (React/Vue):
"proxy": "http://localhost:8081"
```

### Empty Session Data

```bash
# Verify sessions exist
curl http://localhost:8081/api/status

# Check if auth.log is being monitored
tail -f /var/log/auth.log | grep -E 'dropbear|sshd'

# Test SSH connection
ssh user@localhost -p 22
```

---

## Changelog

### v1.2-Stable (2025-01-28)
- Initial API implementation
- 6 endpoints (status, sessions, users, stats, health)
- CORS support
- JSON responses
- Per-user statistics

---

**Last Updated**: 2025-01-28  
**API Version**: v1.2  
**Author**: Risqi Nur Fadhilah
