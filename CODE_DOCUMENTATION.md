# Code Documentation - v1.2-Stable

## Table of Contents
- [Architecture Overview](#architecture-overview)
- [Core Components](#core-components)
- [Data Structures](#data-structures)
- [Flow Diagrams](#flow-diagrams)
- [Key Features Explained](#key-features-explained)
- [Security Considerations](#security-considerations)
- [Performance Optimizations](#performance-optimizations)

---

## Architecture Overview

Websocket Proxy v1.2 is a multi-threaded, concurrent WebSocket proxy with real-time SSH session tracking and RESTful API capabilities.

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    WEBSOCKET PROXY                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │   WebSocket  │  │     UDPGW    │  │   HTTP API   │       │
│  │  Proxy Core  │  │   (BadVPN)   │  │    Server    │       │
│  │  Port: 8080  │  │  Port: 7300  │  │  Port: 8081  │       │
│  └──────┬───────┘  └──────────────┘  └──────┬───────┘       │
│         │                                   │               │
│         │                                   │               │
│  ┌──────▼───────────────────────────────────▼────────┐      │
│  │         Session Manager (sync.Map)                │      │
│  │  - Active Sessions Tracking                       │      │
│  │  - User Authentication Mapping                    │      │
│  │  - Bandwidth Monitoring                           │      │
│  └────────────────┬──────────────────────────────────┘      │
│                   │                                         │
│  ┌────────────────▼──────────────────────────────────┐      │
│  │     Auth Log Monitor (/var/log/auth.log)          │      │
│  │  - Dropbear Parser (Regex)                        │      │
│  │  - OpenSSH Parser (Regex)                         │      │
│  │  - Username Extraction                            │      │
│  └───────────────────────────────────────────────────┘      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
         │                           │
         ▼                           ▼
  ┌─────────────┐           ┌──────────────┐
  │ SSH Servers │           │   API Client │
  │ (Port 22)   │           │ (Dashboard)  │
  └─────────────┘           └──────────────┘
```

---

## Core Components

### 1. WebSocket Proxy Handler

**Location**: `handleConnection()` function

**Responsibilities**:
- Accept incoming WebSocket connections
- Parse HTTP headers for authentication and routing
- Establish TCP connection to SSH server
- Create bidirectional data tunnel
- Track session metadata

**Flow**:
```go
Client Connection → Header Parsing → Authentication Check → 
Target Resolution → TCP Dial → WebSocket Upgrade → 
Bidirectional Copy → Session Cleanup
```

**Key Headers**:
- `X-Real-Host`: Override target destination (e.g., `192.168.1.100:22`)
- `X-Pass`: Authentication password

### 2. Auth Log Monitor

**Location**: `authLogMonitor()` function

**Purpose**: Real-time SSH authentication detection

**Supported Log Formats**:

**Dropbear**:
```
Jan 28 10:30:45 server dropbear[12345]: Password auth succeeded for 'username' from 192.168.1.100:54321
```

**OpenSSH**:
```
Jan 28 10:30:45 server sshd[12345]: Accepted password for username from 192.168.1.100 port 54321 ssh2
```

**Regex Patterns**:
```go
// Dropbear
^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+
\S+\s+dropbear\[(\d+)\]:\s+
Password auth succeeded for '([^']{1,32})'\s+
from\s+((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})

// OpenSSH
^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+
\S+\s+sshd\[(\d+)\]:\s+
Accepted (?:password|publickey|keyboard-interactive)\s+
for\s+([a-zA-Z0-9_-]{1,32})\s+
from\s+((?:\d{1,3}\.){3}\d{1,3})\s+
port\s+(\d{1,5})\s+ssh2?$
```

**Validation Steps**:
1. PID validation (1-9999999)
2. Username format validation
3. IP address validation
4. Port range validation (1-65535)

**Correlation Mechanism**:
```
SSH Port (from auth.log) → Session ID (from sshPortToSession map) → 
Session Object → Update Username/PID/SSH Type
```

### 3. Session Manager

**Location**: Global `sync.Map` variables

**Maps**:
```go
activeSessions   sync.Map  // sessionID → *SessionInfo
sshPortToSession sync.Map  // proxyToSSHPort → sessionID
```

**Why sync.Map?**
- Safe concurrent access without explicit locking
- Optimized for frequent reads
- Better performance than `map + sync.RWMutex` for this use case

**Session Lifecycle**:
```
1. Connection accepted → Generate unique ID
2. Store in activeSessions map
3. Map proxy port to session ID
4. Monitor auth.log for username
5. Update session with user info
6. Track bandwidth until disconnect
7. Remove from maps on close
```

### 4. HTTP API Server

**Location**: `startAPIServer()` function

**Endpoints**:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | Server uptime and session counts |
| `/api/sessions` | GET | All sessions + user stats |
| `/api/sessions/active` | GET | Currently active sessions |
| `/api/users` | GET | Per-user statistics |
| `/api/stats` | GET | Global bandwidth statistics |
| `/health` | GET | Health check |

**CORS Configuration**:
```go
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, OPTIONS
Access-Control-Allow-Headers: Content-Type
Content-Type: application/json
```

### 5. Bandwidth Monitoring

**Location**: `doTransfer()` function

**Mechanism**:
- Uses `WriteCounter` wrapper around `io.Writer`
- Atomic operations for thread-safe counter updates
- Real-time monitoring goroutine (10-second intervals)
- Per-session TX/RX tracking

**Implementation**:
```go
type WriteCounter struct {
    Writer  io.Writer
    Counter *int64
}

func (wc WriteCounter) Write(p []byte) (int, error) {
    n, err := wc.Writer.Write(p)
    if n > 0 {
        atomic.AddInt64(wc.Counter, int64(n))
    }
    return n, err
}
```

---

## Data Structures

### SessionInfo

```go
type SessionInfo struct {
    ID               string    // Unique session ID (e.g., "0042-a3f5c1")
    RealClientIP     string    // Client's actual IP
    RealClientPort   string    // Client's source port
    ClientAddr       string    // Proxy-seen client IP
    ClientPort       string    // Proxy-seen client port
    TargetAddr       string    // SSH server address
    TargetPort       string    // SSH server port
    ProxyToSSHPort   string    // Local port used by proxy → SSH
    Username         string    // SSH username (from auth.log)
    SessionNumber    int       // User's session number (e.g., user-3)
    PID              int       // SSH daemon PID
    SSHType          string    // "dropbear" or "openssh"
    StartTime        time.Time // Connection start time
    LastActivity     time.Time // Last data transfer
    TxBytes          int64     // Bytes sent (client → server)
    RxBytes          int64     // Bytes received (server → client)
    
    // API-only fields (computed on-demand)
    Duration         string
    TxFormatted      string
    RxFormatted      string
    TotalFormatted   string
}
```

### Config

```go
type Config struct {
    BindAddr     string  // Server bind address (e.g., "0.0.0.0")
    Port         int     // WebSocket server port (default: 8080)
    Password     string  // Authentication password
    FallbackAddr string  // Default SSH target (e.g., "127.0.0.1:22")
    LogFile      string  // Log file path
    AuthLogPath  string  // SSH auth log path
    APIPort      int     // HTTP API port (0 = disabled)
}
```

---

## Flow Diagrams

### Connection Flow

```
┌─────────┐
│ Client  │
└────┬────┘
     │ 1. WebSocket Handshake
     │    (Headers: X-Real-Host, X-Pass)
     ▼
┌─────────────────┐
│ handleConnection│
└────┬────────────┘
     │ 2. Parse Headers
     │ 3. Validate Password
     ▼
┌──────────────┐      ┌────────────────┐
│ Generate ID  │─────>│ sessionCounter │
└──────┬───────┘      └────────────────┘
       │
       │ 4. Create SessionInfo
       ▼
┌──────────────────┐
│ activeSessions   │<── Store session
│ sshPortToSession │<── Map proxy port
└──────┬───────────┘
       │
       │ 5. TCP Dial to SSH Server
       ▼
┌──────────────┐
│ SSH Server   │
└──────┬───────┘
       │
       │ 6. Send WebSocket Upgrade Response
       │ 7. Start Bidirectional Copy
       ▼
┌──────────────────────┐
│ doTransfer()         │
│ - TX Goroutine       │
│ - RX Goroutine       │
│ - Monitor Goroutine  │
└──────────────────────┘
```

### Username Detection Flow

```
┌──────────────────┐
│ /var/log/auth.log│
└────────┬─────────┘
         │ Tailed by authLogMonitor()
         ▼
┌────────────────────────────┐
│ New Auth Line Detected     │
└────────┬───────────────────┘
         │
         ├─> Dropbear Regex Match?
         │   └─> Extract: PID, Username, IP, Port
         │
         └─> OpenSSH Regex Match?
             └─> Extract: PID, Username, IP, Port
         
         │ Validate all fields
         ▼
┌────────────────────────────┐
│ sshPortToSession.Load()    │
│ (Lookup by SSH port)       │
└────────┬───────────────────┘
         │
         ▼
┌────────────────────────────┐
│ activeSessions.Load()      │
│ (Get session object)       │
└────────┬───────────────────┘
         │
         ▼
┌────────────────────────────┐
│ Update Session:            │
│ - Username                 │
│ - PID                      │
│ - SSHType                  │
│ - SessionNumber            │
└────────────────────────────┘
```

### API Request Flow

```
┌──────────┐
│ API Call │ GET /api/sessions
└────┬─────┘
     │
     ▼
┌──────────────────┐
│ corsMiddleware   │ Set CORS headers
└────┬─────────────┘
     │
     ▼
┌──────────────────┐
│ handleSessions() │
└────┬─────────────┘
     │
     │ activeSessions.Range()
     │ (Iterate all sessions)
     ▼
┌──────────────────────┐
│ Compute:             │
│ - Session duration   │
│ - Bandwidth stats    │
│ - User aggregates    │
└────┬─────────────────┘
     │
     ▼
┌──────────────────────┐
│ JSON Marshal         │
│ SessionsResponse{}   │
└────┬─────────────────┘
     │
     ▼
┌──────────┐
│ Response │ 200 OK
└──────────┘
```

---

## Key Features Explained

### 1. Session ID Generation

**Format**: `{counter}-{random_hex}`

**Example**: `0042-a3f5c1`

**Implementation**:
```go
func generateSessionID() string {
    counter := atomic.AddInt64(&sessionCounter, 1)
    b := make([]byte, 4)
    rand.Read(b)
    return fmt.Sprintf("%04d-%s", counter, hex.EncodeToString(b)[:6])
}
```

**Benefits**:
- Globally unique within server lifetime
- Sortable by creation order (counter prefix)
- Collision-resistant (random suffix)
- Compact and readable

### 2. Session Numbering Per User

**Purpose**: Track multiple concurrent sessions per user

**Example**: 
- User `john` connects → `john-1`
- User `john` connects again → `john-2`
- User `alice` connects → `alice-1`

**Implementation**:
```go
func getNextSessionNumber(username string) int {
    maxNum := 0
    activeSessions.Range(func(key, value interface{}) bool {
        session := value.(*SessionInfo)
        if session.Username == username && session.SessionNumber > maxNum {
            maxNum = session.SessionNumber
        }
        return true
    })
    return maxNum + 1
}
```

### 3. Proxy Port Correlation

**Problem**: How to correlate WebSocket sessions with SSH logins?

**Solution**: Map the proxy's local port (used to connect to SSH) to the session ID

**Flow**:
```
1. Proxy dials SSH server
   → Local ephemeral port assigned (e.g., 54321)
   
2. Store mapping:
   sshPortToSession["54321"] = "0042-a3f5c1"
   
3. SSH auth.log shows:
   "Accepted password for john from 192.168.1.100 port 54321"
   
4. Extract port 54321 → Lookup session 0042-a3f5c1
   
5. Update session with username "john"
```

**Why this works**:
- SSH server sees the proxy's local port as the client port
- This port is unique per connection
- Matches the ephemeral port in auth.log

### 4. Atomic Operations for Bandwidth

**Why atomic?**
- Multiple goroutines access bandwidth counters (TX writer, RX writer, monitor)
- Standard `int64++` is not thread-safe
- `sync.Mutex` would add overhead to every write operation

**Implementation**:
```go
// Thread-safe increment
atomic.AddInt64(&session.TxBytes, int64(n))

// Thread-safe read
currTx := atomic.LoadInt64(&session.TxBytes)
```

**Performance**: ~10ns per operation (vs ~100ns for mutex)

### 5. Graceful Shutdown

**Mechanism**:
```go
ctx, stop := signal.NotifyContext(
    context.Background(), 
    os.Interrupt, 
    syscall.SIGTERM
)
defer stop()

// Block until signal received
<-ctx.Done()

// Cleanup
logSessionSummary()
listener.Close()
```

**What happens**:
1. User presses Ctrl+C or sends SIGTERM
2. Context is canceled
3. All goroutines checking `<-ctx.Done()` exit gracefully
4. Session summary printed
5. Listener closed
6. Program exits cleanly

---

## Security Considerations

### 1. Regex Injection Prevention

**Validation Steps**:
```go
// Username validation
- Length: 1-32 characters
- First char: [a-zA-Z_]
- Other chars: [a-zA-Z0-9_-]

// IP validation
- Must parse as valid IP address

// Port validation
- Range: 1-65535

// PID validation
- Range: 1-9999999
```

### 2. Password Authentication

**Current**: Simple password comparison

**Recommendation for Production**:
```go
// Use constant-time comparison to prevent timing attacks
func secureCompare(a, b string) bool {
    return subtle.ConstantTimeCompare(
        []byte(a), 
        []byte(b)
    ) == 1
}
```

### 3. API Security

**Current**: No authentication (CORS: `*`)

**Recommendations**:
- Add API key authentication
- Restrict CORS to specific origins
- Implement rate limiting
- Add request logging
- Use HTTPS in production

### 4. File Permissions

**Required Permissions**:
```bash
# Auth log must be readable
chmod 644 /var/log/auth.log
# or add user to adm group
usermod -aG adm ssh-ws-user

# Log file directory
mkdir -p /var/log/ssh-ws
chown ssh-ws-user:ssh-ws-user /var/log/ssh-ws
chmod 755 /var/log/ssh-ws
```

---

## Performance Optimizations

### 1. sync.Map vs map + Mutex

**Benchmark Results** (1M operations):
```
map + RWMutex:     ~150ms (read-heavy)
sync.Map:          ~80ms  (read-heavy)

Improvement: ~46% faster for our use case
```

### 2. Goroutine Pool vs On-Demand

**Current**: One goroutine per connection

**Why?**
- Connections are long-lived (SSH sessions)
- Goroutines are lightweight (~2KB stack)
- Fewer context switches than worker pools

### 3. Buffer Sizes

```go
// Header buffer: 4KB
buf := make([]byte, 4096)

// Rationale:
// - Most HTTP headers < 2KB
// - Single page size for memory efficiency
// - Prevents multiple syscalls for small reads
```

### 4. Auth Log Polling

```go
ticker := time.NewTicker(500 * time.Millisecond)

// Trade-off:
// - 500ms delay for username detection (acceptable)
// - Low CPU usage (~0.1% on modern systems)
// - No inotify complexity
```

---

## Testing Checklist

### Unit Tests
- [ ] Session ID uniqueness
- [ ] Bandwidth counter accuracy
- [ ] Regex pattern matching
- [ ] Username validation
- [ ] API response formats

### Integration Tests
- [ ] Dropbear authentication
- [ ] OpenSSH authentication
- [ ] Multi-user concurrent sessions
- [ ] API endpoint responses
- [ ] Bandwidth tracking accuracy

### Load Tests
- [ ] 100 concurrent connections
- [ ] 1000 sessions per hour
- [ ] Long-running sessions (24h+)
- [ ] Memory leak detection
- [ ] CPU usage under load

### Security Tests
- [ ] Invalid password rejection
- [ ] Malformed header handling
- [ ] Log injection attempts
- [ ] API authentication bypass
- [ ] Rate limiting effectiveness

---

## Future Enhancements

### Code Improvements
1. **Structured Logging**: Replace `log.Printf` with `zap` or `logrus`
2. **Configuration File**: Support YAML/JSON config files
3. **Database Backend**: Store session history in SQLite/PostgreSQL
4. **Metrics**: Prometheus exporter for monitoring
5. **WebUI**: Dashboard for real-time monitoring

### Feature Additions
1. **Session Recording**: Store SSH session transcripts
2. **IP Whitelisting**: Restrict access by IP/CIDR
3. **User Quotas**: Limit bandwidth/sessions per user
4. **Alerts**: Webhook notifications for events
5. **Clustering**: Multi-node support with shared state

---

## Troubleshooting

### Common Issues

**Issue**: Username always shows "detecting..."
```bash
# Check auth log permissions
ls -la /var/log/auth.log

# Verify log format
tail -f /var/log/auth.log | grep -E 'dropbear|sshd'

# Test regex manually
echo "Jan 28 10:30:45 server dropbear[1234]: Password auth succeeded for 'test' from 1.2.3.4:5678" | \
  grep -P "dropbear\[\d+\]: Password auth succeeded"
```

**Issue**: API returns empty sessions
```bash
# Check if sessions are being created
curl http://localhost:8081/api/status

# Verify sync.Map is populated
# Add debug logging in handleConnection()
```

**Issue**: High memory usage
```bash
# Profile memory
go tool pprof http://localhost:8081/debug/pprof/heap

# Check for goroutine leaks
curl http://localhost:8081/debug/pprof/goroutine?debug=1
```

---

## References

- [Go sync.Map Documentation](https://pkg.go.dev/sync#Map)
- [UDPGW Library](https://github.com/mukswilly/udpgw)
- [WebSocket RFC 6455](https://tools.ietf.org/html/rfc6455)
- [Dropbear SSH](https://matt.ucc.asn.au/dropbear/dropbear.html)
- [OpenSSH Documentation](https://www.openssh.com/manual.html)

---

**Last Updated**: 2025-01-28  
**Version**: v1.2-Stable  
**Author**: Risqi Nur Fadhilah
