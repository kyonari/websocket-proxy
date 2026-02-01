/*
 * Copyright (c) 2025 Risqi Nur Fadhilah
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * ----------------------------------------------------------------------------
 * Project      : GO-TUNNEL PRO
 * Developers   : Risqi Nur Fadhilah
 * Tester       : Rerechan02
 * Version      : v1.2-Stable
 * License      : MIT License
 * ----------------------------------------------------------------------------
 *
 * CMD Compile:
 * CGO_ENABLED=0 go build -ldflags "-s -w -X 'main.Credits=Risqi Nur Fadhilah' -X 'main.Version=v1.2-Stable'" -o ssh-ws
 *
 * Requirements:
 * - Debian 11 / Ubuntu 22.04+
 * - Go version 1.22.0 or higher
 * - Dropbear or OpenSSH server
 * - Access to /var/log/auth.log
 */

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mukswilly/udpgw"
)

var (
	Version = "v2.6-Stable"
	Credits = "Risqi Nur Fadhilah"
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
	ColorGray   = "\033[90m"
	ColorPurple = "\033[35m"
	ColorBlue   = "\033[34m"
	ColorWhite  = "\033[97m"
	ColorBold   = "\033[1m"
	
	PayloadResponse = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
)

type Config struct {
	BindAddr     string
	Port         int
	Password     string
	FallbackAddr string
	LogFile      string
	AuthLogPath  string
	APIPort      int
}

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

type SessionInfo struct {
	ID               string    `json:"id"`
	RealClientIP     string    `json:"real_client_ip"`
	RealClientPort   string    `json:"real_client_port"`
	ClientAddr       string    `json:"client_addr"`
	ClientPort       string    `json:"client_port"`
	TargetAddr       string    `json:"target_addr"`
	TargetPort       string    `json:"target_port"`
	ProxyToSSHPort   string    `json:"proxy_to_ssh_port"`
	Username         string    `json:"username"`
	SessionNumber    int       `json:"session_number"`
	PID              int       `json:"pid"`
	SSHType          string    `json:"ssh_type"`
	StartTime        time.Time `json:"start_time"`
	LastActivity     time.Time `json:"last_activity"`
	TxBytes          int64     `json:"tx_bytes"`
	RxBytes          int64     `json:"rx_bytes"`
	Duration         string    `json:"duration"`
	TxFormatted      string    `json:"tx_formatted"`
	RxFormatted      string    `json:"rx_formatted"`
	TotalFormatted   string    `json:"total_formatted"`
}

type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type SessionsResponse struct {
	TotalSessions   int64                  `json:"total_sessions"`
	ActiveSessions  int                    `json:"active_sessions"`
	ClosedSessions  int64                  `json:"closed_sessions"`
	Sessions        []SessionInfo          `json:"sessions"`
	UserStats       map[string]UserStats   `json:"user_stats"`
}

type UserStats struct {
	Username       string `json:"username"`
	SessionCount   int    `json:"session_count"`
	TotalTX        int64  `json:"total_tx"`
	TotalRX        int64  `json:"total_rx"`
	TotalBytes     int64  `json:"total_bytes"`
	TxFormatted    string `json:"tx_formatted"`
	RxFormatted    string `json:"rx_formatted"`
	TotalFormatted string `json:"total_formatted"`
}

var (
	activeSessions   sync.Map
	sessionCounter   int64
	sshPortToSession sync.Map
	serverStartTime  time.Time
)

func main() {
	cfg := setupFlags()
	
	setupLogger(cfg.LogFile)
	serverStartTime = time.Now()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	printProxyBanner()

	if cfg.APIPort > 0 {
		go startAPIServer(cfg.APIPort)
	}

	go sessionMonitor(ctx)
	
	go authLogMonitor(ctx, cfg.AuthLogPath)

	go func() {
		configJSON := fmt.Sprintf(`{
			"LogLevel": "info",
			"LogFilename": "%s",
			"HostID": "proxy-server",
			"UdpgwPort": 7300,
			"DNSResolverIPAddress": "1.1.1.1"
		}`, cfg.LogFile)
		
		logInfo("UDPGW", "Initializing Multiplexer on port 7300...")
		if err := udpgw.StartServer([]byte(configJSON)); err != nil {
			logError("UDPGW", fmt.Sprintf("Service Error: %v", err))
		}
	}()

	serverAddr := fmt.Sprintf("%s:%d", cfg.BindAddr, cfg.Port)
	listener, err := net.Listen("tcp", serverAddr)
	if err != nil {
		logError("CORE", fmt.Sprintf("Failed to bind %s: %v", serverAddr, err))
		os.Exit(1)
	}

	go func() {
		logInfo("SSHWS", fmt.Sprintf("Listening on %s%s%s", ColorCyan, serverAddr, ColorReset))
		logInfo("AUTH", fmt.Sprintf("Monitoring: %s%s%s", ColorCyan, cfg.AuthLogPath, ColorReset))
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}
			go handleConnection(conn, cfg)
		}
	}()

	<-ctx.Done()
	fmt.Println("\n" + ColorYellow + " [!] Shutdown signal received. Closing all connections..." + ColorReset)
	logSessionSummary()
	listener.Close()
	time.Sleep(1 * time.Second)
	logInfo("SYSTEM", "Server halted successfully.")
}

func startAPIServer(port int) {
	mux := http.NewServeMux()
	
	corsMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Content-Type", "application/json")
			
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}
			next(w, r)
		}
	}
	
	mux.HandleFunc("/api/status", corsMiddleware(handleStatus))
	mux.HandleFunc("/api/sessions", corsMiddleware(handleSessions))
	mux.HandleFunc("/api/sessions/active", corsMiddleware(handleActiveSessions))
	mux.HandleFunc("/api/users", corsMiddleware(handleUsers))
	mux.HandleFunc("/api/stats", corsMiddleware(handleStats))
	mux.HandleFunc("/health", corsMiddleware(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "OK"})
	}))
	
	addr := fmt.Sprintf(":%d", port)
	logInfo("API", fmt.Sprintf("HTTP API listening on %s%s%s", ColorCyan, addr, ColorReset))
	
	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logError("API", fmt.Sprintf("Server error: %v", err))
	}
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	activeCount := 0
	activeSessions.Range(func(key, value interface{}) bool {
		activeCount++
		return true
	})
	
	totalSessions := atomic.LoadInt64(&sessionCounter)
	uptime := time.Since(serverStartTime)
	
	data := map[string]interface{}{
		"version":         Version,
		"uptime":          uptime.String(),
		"uptime_seconds":  int(uptime.Seconds()),
		"total_sessions":  totalSessions,
		"active_sessions": activeCount,
		"closed_sessions": totalSessions - int64(activeCount),
	}
	
	json.NewEncoder(w).Encode(APIResponse{Success: true, Data: data})
}

func handleSessions(w http.ResponseWriter, r *http.Request) {
	sessions := []SessionInfo{}
	userStats := make(map[string]UserStats)
	
	activeSessions.Range(func(key, value interface{}) bool {
		session := value.(*SessionInfo)
		duration := time.Since(session.StartTime)
		txBytes := atomic.LoadInt64(&session.TxBytes)
		rxBytes := atomic.LoadInt64(&session.RxBytes)
		
		sessionInfo := SessionInfo{
			ID:             session.ID,
			RealClientIP:   session.RealClientIP,
			RealClientPort: session.RealClientPort,
			Username:       session.Username,
			SessionNumber:  session.SessionNumber,
			PID:            session.PID,
			SSHType:        session.SSHType,
			StartTime:      session.StartTime,
			TxBytes:        txBytes,
			RxBytes:        rxBytes,
			Duration:       duration.Round(time.Second).String(),
			TxFormatted:    formatBytes(txBytes),
			RxFormatted:    formatBytes(rxBytes),
			TotalFormatted: formatBytes(txBytes + rxBytes),
		}
		sessions = append(sessions, sessionInfo)
		
		if session.Username != "detecting..." && session.Username != "" {
			stats := userStats[session.Username]
			stats.Username = session.Username
			stats.SessionCount++
			stats.TotalTX += txBytes
			stats.TotalRX += rxBytes
			stats.TotalBytes = stats.TotalTX + stats.TotalRX
			stats.TxFormatted = formatBytes(stats.TotalTX)
			stats.RxFormatted = formatBytes(stats.TotalRX)
			stats.TotalFormatted = formatBytes(stats.TotalBytes)
			userStats[session.Username] = stats
		}
		
		return true
	})
	
	totalSessions := atomic.LoadInt64(&sessionCounter)
	response := SessionsResponse{
		TotalSessions:  totalSessions,
		ActiveSessions: len(sessions),
		ClosedSessions: totalSessions - int64(len(sessions)),
		Sessions:       sessions,
		UserStats:      userStats,
	}
	
	json.NewEncoder(w).Encode(APIResponse{Success: true, Data: response})
}

func handleActiveSessions(w http.ResponseWriter, r *http.Request) {
	sessions := []SessionInfo{}
	
	activeSessions.Range(func(key, value interface{}) bool {
		session := value.(*SessionInfo)
		duration := time.Since(session.StartTime)
		txBytes := atomic.LoadInt64(&session.TxBytes)
		rxBytes := atomic.LoadInt64(&session.RxBytes)
		
		sessionInfo := SessionInfo{
			ID:             session.ID,
			RealClientIP:   session.RealClientIP,
			Username:       session.Username,
			SessionNumber:  session.SessionNumber,
			PID:            session.PID,
			SSHType:        session.SSHType,
			Duration:       duration.Round(time.Second).String(),
			TxFormatted:    formatBytes(txBytes),
			RxFormatted:    formatBytes(rxBytes),
			TotalFormatted: formatBytes(txBytes + rxBytes),
		}
		sessions = append(sessions, sessionInfo)
		return true
	})
	
	json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Data:    map[string]interface{}{"count": len(sessions), "sessions": sessions},
	})
}

func handleUsers(w http.ResponseWriter, r *http.Request) {
	userStats := make(map[string]UserStats)
	
	activeSessions.Range(func(key, value interface{}) bool {
		session := value.(*SessionInfo)
		if session.Username != "detecting..." && session.Username != "" {
			txBytes := atomic.LoadInt64(&session.TxBytes)
			rxBytes := atomic.LoadInt64(&session.RxBytes)
			
			stats := userStats[session.Username]
			stats.Username = session.Username
			stats.SessionCount++
			stats.TotalTX += txBytes
			stats.TotalRX += rxBytes
			stats.TotalBytes = stats.TotalTX + stats.TotalRX
			stats.TxFormatted = formatBytes(stats.TotalTX)
			stats.RxFormatted = formatBytes(stats.TotalRX)
			stats.TotalFormatted = formatBytes(stats.TotalBytes)
			userStats[session.Username] = stats
		}
		return true
	})
	
	userList := []UserStats{}
	for _, stats := range userStats {
		userList = append(userList, stats)
	}
	
	json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Data:    map[string]interface{}{"count": len(userList), "users": userList},
	})
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	var totalTX, totalRX int64
	activeCount := 0
	userCounts := make(map[string]int)
	
	activeSessions.Range(func(key, value interface{}) bool {
		activeCount++
		session := value.(*SessionInfo)
		totalTX += atomic.LoadInt64(&session.TxBytes)
		totalRX += atomic.LoadInt64(&session.RxBytes)
		
		if session.Username != "detecting..." && session.Username != "" {
			userCounts[session.Username]++
		}
		return true
	})
	
	totalSessions := atomic.LoadInt64(&sessionCounter)
	uptime := time.Since(serverStartTime)
	
	data := map[string]interface{}{
		"uptime":           uptime.String(),
		"uptime_seconds":   int(uptime.Seconds()),
		"total_sessions":   totalSessions,
		"active_sessions":  activeCount,
		"closed_sessions":  totalSessions - int64(activeCount),
		"total_tx":         totalTX,
		"total_rx":         totalRX,
		"total_bytes":      totalTX + totalRX,
		"tx_formatted":     formatBytes(totalTX),
		"rx_formatted":     formatBytes(totalRX),
		"total_formatted":  formatBytes(totalTX + totalRX),
		"unique_users":     len(userCounts),
		"users_breakdown":  userCounts,
	}
	
	json.NewEncoder(w).Encode(APIResponse{Success: true, Data: data})
}

func handleConnection(clientConn net.Conn, cfg Config) {
	defer clientConn.Close()

	// 1. Setup KeepAlive agar koneksi tidak mudah putus (Fix Idle EOF)
	if tcpConn, ok := clientConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	sessionID := generateSessionID()
	clientAddr := clientConn.RemoteAddr().String()
	clientIP, clientPort := splitHostPort(clientAddr)

	// 2. Perbesar Buffer ke 16KB (Fix Payload Panjang)
	// Payload unik seringkali punya header > 4KB
	clientConn.SetReadDeadline(time.Now().Add(10 * time.Second)) // Tambah waktu tunggu jadi 10 detik
	buf := make([]byte, 16384) 
	n, err := clientConn.Read(buf)
	if err != nil {
		return
	}
	
	clientConn.SetReadDeadline(time.Time{})

	// 3. Pisahkan Header dan Body (Fix Data Swallowing)
	// Kita cari batas akhir HTTP Header (\r\n\r\n)
	// Jika injektor mengirim SSH Hello (SSH-2.0...) nempel di belakang payload,
	// kita harus simpan datanya di variabel 'leftover'
	var rawHeaders string
	var leftover []byte

	sep := []byte("\r\n\r\n")
	splitPos := bytes.Index(buf[:n], sep)

	if splitPos != -1 {
		// Header ditemukan, ambil sampai batas
		rawHeaders = string(buf[:splitPos+4])
		// Ambil sisa data (jika ada)
		if n > splitPos+4 {
			leftover = buf[splitPos+4 : n]
		}
	} else {
		// Jika tidak ketemu \r\n\r\n, anggap semua adalah header (fallback)
		rawHeaders = string(buf[:n])
	}

	realClientIP := clientIP
	realClientPort := clientPort
	
	targetHost := getHeader(rawHeaders, "X-Real-Host")
	if targetHost == "" { 
		targetHost = cfg.FallbackAddr 
	}

	authPass := getHeader(rawHeaders, "X-Pass")
	if cfg.Password != "" && authPass != cfg.Password {
		logWarn("AUTH", fmt.Sprintf("[%s] Unauthorized from %s:%s", sessionID, realClientIP, realClientPort))
		clientConn.Write([]byte("HTTP/1.1 401 Unauthorized\r\n\r\n"))
		return
	}

	if !strings.Contains(targetHost, ":") { 
		targetHost += ":22" 
	}
	_, targetPort := splitHostPort(targetHost)

	// Koneksi ke Target (Dropbear/OpenSSH)
	targetConn, err := net.DialTimeout("tcp", targetHost, 10*time.Second)
	if err != nil {
		logError("TUNNEL", fmt.Sprintf("[%s] Failed to reach %s from %s:%s", sessionID, targetHost, realClientIP, realClientPort))
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer targetConn.Close()

	proxyLocalAddr := targetConn.LocalAddr().String()
	_, proxyToSSHPort := splitHostPort(proxyLocalAddr)

	session := &SessionInfo{
		ID:             sessionID,
		RealClientIP:   realClientIP,
		RealClientPort: realClientPort,
		ClientAddr:     clientIP,
		ClientPort:     clientPort,
		TargetAddr:     targetHost,
		TargetPort:     targetPort,
		ProxyToSSHPort: proxyToSSHPort,
		Username:       "detecting...",
		SessionNumber:  0,
		PID:            0,
		SSHType:        "unknown",
		StartTime:      time.Now(),
		LastActivity:   time.Now(),
	}
	activeSessions.Store(sessionID, session)
	sshPortToSession.Store(proxyToSSHPort, sessionID)

	logSuccess("CONNECT", fmt.Sprintf("[%s] %s:%s -> %s (proxy port:%s)", 
		sessionID, realClientIP, realClientPort, targetHost, proxyToSSHPort))
	
	// Balas HTTP 101 Switching Protocols ke Client
	clientConn.Write([]byte(PayloadResponse))

	// 4. KRUSIAL: Kirim sisa data (leftover) ke Target SEBELUM transfer dimulai
	// Ini yang memperbaiki masalah EOF jika payload dan SSH Hello dikirim bersamaan
	if len(leftover) > 0 {
		_, err = targetConn.Write(leftover)
		if err != nil {
			logError("TUNNEL", fmt.Sprintf("[%s] Failed to write leftover bytes: %v", sessionID, err))
			return
		}
		// Tambahkan ke statistik upload
		atomic.AddInt64(&session.TxBytes, int64(len(leftover)))
	}

	doTransfer(clientConn, targetConn, session)
	sshPortToSession.Delete(proxyToSSHPort)
}

func getNextSessionNumber(username string) int {
	if username == "" || username == "detecting..." {
		return 0
	}
	
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

func formatUserDisplay(username string, sessionNumber int, pid int) string {
	userInfo := username
	
	if username != "detecting..." && username != "" && sessionNumber > 0 {
		userInfo = fmt.Sprintf("%s-%d", username, sessionNumber)
	}
	
	if pid > 0 {
		userInfo = fmt.Sprintf("%s (PID:%d)", userInfo, pid)
	}
	
	return userInfo
}

func doTransfer(client, target net.Conn, session *SessionInfo) {
	var wg sync.WaitGroup
	wg.Add(2)

	stopMonitor := make(chan bool)

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		
		for {
			select {
			case <-stopMonitor:
				return
			case <-ticker.C:
				currTx := atomic.LoadInt64(&session.TxBytes)
				currRx := atomic.LoadInt64(&session.RxBytes)
				if currTx > 0 || currRx > 0 {
					session.LastActivity = time.Now()
					duration := time.Since(session.StartTime).Round(time.Second)
					
					userInfo := formatUserDisplay(session.Username, session.SessionNumber, session.PID)
					totalBytes := currTx + currRx
					
					log.Printf("%s[MONITOR]%s [%s] %s:%s | User: %s | Duration: %v | TX: %s | RX: %s | Total: %s", 
						ColorPurple, ColorReset, session.ID, session.RealClientIP, session.RealClientPort,
						userInfo, duration, formatBytes(currTx), formatBytes(currRx), formatBytes(totalBytes))
				}
			}
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(WriteCounter{target, &session.TxBytes}, client)
		if t, ok := target.(*net.TCPConn); ok { 
			t.CloseWrite() 
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(WriteCounter{client, &session.RxBytes}, target)
		if c, ok := client.(*net.TCPConn); ok { 
			c.CloseWrite() 
		}
	}()

	wg.Wait()
	stopMonitor <- true
	
	duration := time.Since(session.StartTime).Round(time.Second)
	totalTx := atomic.LoadInt64(&session.TxBytes)
	totalRx := atomic.LoadInt64(&session.RxBytes)
	totalBytes := totalTx + totalRx
	
	userInfo := formatUserDisplay(session.Username, session.SessionNumber, session.PID)
	
	log.Printf("%s[END]%s [%s] %s:%s | User: %s%s%s | Duration: %v | TX: %s | RX: %s | Total: %s", 
		ColorGray, ColorReset, session.ID, session.RealClientIP, session.RealClientPort,
		ColorBold, userInfo, ColorReset,
		duration, formatBytes(totalTx), formatBytes(totalRx), 
		formatBytes(totalBytes))
	
	activeSessions.Delete(session.ID)
}

func authLogMonitor(ctx context.Context, authLogPath string) {
	dropbearRegex := regexp.MustCompile(
		`^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+` +
		`\S+\s+` +
		`dropbear\[(\d+)\]:\s+` +
		`Password auth succeeded for '([^']{1,32})'\s+` +
		`from\s+((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})`,
	)
	
	opensshRegex := regexp.MustCompile(
		`^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+` +
		`\S+\s+` +
		`sshd\[(\d+)\]:\s+` +
		`Accepted (?:password|publickey|keyboard-interactive)\s+` +
		`for\s+([a-zA-Z0-9_-]{1,32})\s+` +
		`from\s+((?:\d{1,3}\.){3}\d{1,3})\s+` +
		`port\s+(\d{1,5})\s+` +
		`ssh2?$`,
	)
	
	file, err := os.Open(authLogPath)
	if err != nil {
		logWarn("AUTH", fmt.Sprintf("Cannot open %s: %v (username detection disabled)", authLogPath, err))
		return
	}
	defer file.Close()
	
	file.Seek(0, io.SeekEnd)
	reader := bufio.NewReader(file)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					break
				}
				
				if matches := dropbearRegex.FindStringSubmatch(line); len(matches) == 5 {
					pidStr := matches[1]
					username := matches[2]
					ipAddr := matches[3]
					portStr := matches[4]
					
					if !isStrictValidDropbearMatch(pidStr, username, ipAddr, portStr) {
						continue
					}
					
					pid, _ := strconv.Atoi(pidStr)
					updateSessionUsername(pid, username, portStr, "dropbear")
				}
				
				if matches := opensshRegex.FindStringSubmatch(line); len(matches) == 5 {
					pidStr := matches[1]
					username := matches[2]
					ipAddr := matches[3]
					portStr := matches[4]
					
					if !isStrictValidOpenSSHMatch(pidStr, username, ipAddr, portStr) {
						continue
					}
					
					pid, _ := strconv.Atoi(pidStr)
					updateSessionUsername(pid, username, portStr, "openssh")
				}
			}
		}
	}
}

func isStrictValidDropbearMatch(pidStr, username, ipAddr, portStr string) bool {
	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid < 1 || pid > 9999999 {
		return false
	}
	
	if len(username) < 1 || len(username) > 32 {
		return false
	}
	for _, c := range username {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	
	if net.ParseIP(ipAddr) == nil {
		return false
	}
	
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return false
	}
	
	return true
}

func isStrictValidOpenSSHMatch(pidStr, username, ipAddr, portStr string) bool {
	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid < 1 || pid > 9999999 {
		return false
	}
	
	if len(username) < 1 || len(username) > 32 {
		return false
	}
	if !((username[0] >= 'a' && username[0] <= 'z') || 
		(username[0] >= 'A' && username[0] <= 'Z') || 
		username[0] == '_') {
		return false
	}
	for _, c := range username {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
			(c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	
	if net.ParseIP(ipAddr) == nil {
		return false
	}
	
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return false
	}
	
	return true
}

func updateSessionUsername(pid int, username, sshSeesPort, sshType string) {
	if sessionID, ok := sshPortToSession.Load(sshSeesPort); ok {
		if sessionVal, exists := activeSessions.Load(sessionID); exists {
			session := sessionVal.(*SessionInfo)
			session.Username = username
			session.PID = pid
			session.SSHType = sshType
			
			if session.SessionNumber == 0 {
				session.SessionNumber = getNextSessionNumber(username)
			}
			
			activeSessions.Store(sessionID, session)
			
			sshTypeDisplay := ""
			if sshType == "dropbear" {
				sshTypeDisplay = " [Dropbear]"
			} else if sshType == "openssh" {
				sshTypeDisplay = " [OpenSSH]"
			}
			
			userDisplay := formatUserDisplay(username, session.SessionNumber, pid)
			
			logInfo("AUTH", fmt.Sprintf("[%s] User authenticated: %s%s%s%s", 
				session.ID, ColorBold, userDisplay, ColorReset, sshTypeDisplay))
		}
	}
}

func splitHostPort(addr string) (host, port string) {
	lastColon := strings.LastIndex(addr, ":")
	if lastColon == -1 {
		return addr, ""
	}
	return addr[:lastColon], addr[lastColon+1:]
}

func generateSessionID() string {
	counter := atomic.AddInt64(&sessionCounter, 1)
	b := make([]byte, 4)
	rand.Read(b)
	return fmt.Sprintf("%04d-%s", counter, hex.EncodeToString(b)[:6])
}

func sessionMonitor(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			count := 0
			var userList []string
			
			activeSessions.Range(func(key, value interface{}) bool {
				count++
				session := value.(*SessionInfo)
				if session.Username != "detecting..." && session.Username != "" && session.SessionNumber > 0 {
					userList = append(userList, fmt.Sprintf("%s-%d", session.Username, session.SessionNumber))
				}
				return true
			})
			
			if count > 0 {
				userStats := strings.Join(userList, ", ")
				if userStats == "" {
					userStats = "authenticating..."
				}
				
				logInfo("MONITOR", fmt.Sprintf("Active sessions: %s%d%s [%s]", 
					ColorBold, count, ColorReset, userStats))
			}
		}
	}
}

func logSessionSummary() {
	fmt.Println("\n" + ColorCyan + "═══════════════════════════════════════════════════════" + ColorReset)
	fmt.Println(ColorCyan + "                 SESSION SUMMARY" + ColorReset)
	fmt.Println(ColorCyan + "═══════════════════════════════════════════════════════" + ColorReset)
	
	totalSessions := atomic.LoadInt64(&sessionCounter)
	activeCount := 0
	userStats := make(map[string]struct {
		Count   int
		TotalTX int64
		TotalRX int64
	})
	
	activeSessions.Range(func(key, value interface{}) bool {
		activeCount++
		session := value.(*SessionInfo)
		duration := time.Since(session.StartTime).Round(time.Second)
		
		userInfo := formatUserDisplay(session.Username, session.SessionNumber, session.PID)
		
		fmt.Printf("  [%s] %s:%s | User: %s | Duration: %v | TX: %s | RX: %s\n",
			session.ID, session.RealClientIP, session.RealClientPort, userInfo, duration,
			formatBytes(atomic.LoadInt64(&session.TxBytes)),
			formatBytes(atomic.LoadInt64(&session.RxBytes)))
		
		if session.Username != "detecting..." && session.Username != "" {
			stats := userStats[session.Username]
			stats.Count++
			stats.TotalTX += atomic.LoadInt64(&session.TxBytes)
			stats.TotalRX += atomic.LoadInt64(&session.RxBytes)
			userStats[session.Username] = stats
		}
		
		return true
	})
	
	if len(userStats) > 0 {
		fmt.Println("\n  Per-User Statistics:")
		for user, stats := range userStats {
			fmt.Printf("    %s: %d sessions | TX: %s | RX: %s | Total: %s\n",
				user, stats.Count, formatBytes(stats.TotalTX), formatBytes(stats.TotalRX),
				formatBytes(stats.TotalTX+stats.TotalRX))
		}
	}
	
	fmt.Printf("\n  Total Sessions: %d | Active: %d | Closed: %d\n",
		totalSessions, activeCount, totalSessions-int64(activeCount))
	fmt.Println(ColorCyan + "═══════════════════════════════════════════════════════" + ColorReset)
}

func setupFlags() Config {
	c := Config{}
	var logF1, logF2, logF3 string

	flag.StringVar(&c.BindAddr, "b", "0.0.0.0", "Bind Address")
	flag.IntVar(&c.Port, "p", 8080, "Port server")
	flag.StringVar(&c.Password, "a", "", "Auth Password")
	flag.StringVar(&c.FallbackAddr, "t", "127.0.0.1:22", "Default Target")
	flag.StringVar(&c.AuthLogPath, "auth-log", "/var/log/auth.log", "Auth log path")
	flag.IntVar(&c.APIPort, "api-port", 8081, "HTTP API port (0 to disable)")
	
	flag.StringVar(&logF1, "l", "", "Log file path")
	flag.StringVar(&logF2, "log", "", "Log file path")
	flag.StringVar(&logF3, "logs", "", "Log file path")
	
	flag.Parse()

	if logF1 != "" { 
		c.LogFile = logF1 
	} else if logF2 != "" { 
		c.LogFile = logF2 
	} else { 
		c.LogFile = logF3 
	}
	
	return c
}

func setupLogger(path string) {
	writers := []io.Writer{os.Stdout}
	if path != "" {
		_ = os.MkdirAll(filepath.Dir(path), 0755)
		file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil { 
			writers = append(writers, file) 
		}
	}
	log.SetOutput(io.MultiWriter(writers...))
	log.SetFlags(log.Ldate | log.Ltime)
}

func printProxyBanner() {
	fmt.Print(ColorCyan)
	fmt.Println(`╔════════════════════════════════════════════════════════╗`)
	fmt.Println(`║    ___  ___  ____  _  ____  __                         `)
	fmt.Println(`║   / _ \/ _ \/ __ \| |/ /\ \/ /                         `)
	fmt.Println(`║  / ___/ , _/ /_/ /  |   \  /                           `)
	fmt.Println(`║ /_/  /_/|_|\____/_/|_|   /_/                           `)
	fmt.Println(`║                                                        `)
	fmt.Printf("║  %s  VERSION   : %-37s %s\n", ColorGray, Version, ColorCyan)
	fmt.Printf("║  %s  DEVELOPER : %-37s %s\n", ColorGray, Credits, ColorCyan)
//	fmt.Println(`║  %s  FEATURES  : Dropbear + OpenSSH + Real IP + API    %s`, ColorGray, ColorCyan)
	fmt.Println(`╚════════════════════════════════════════════════════════╝`)
	fmt.Print(ColorReset)
}

func logInfo(tag, m string)    { log.Printf("%s[%s]%s %s", ColorBlue, tag, ColorReset, m) }
func logSuccess(tag, m string) { log.Printf("%s[%s]%s %s", ColorGreen, tag, ColorReset, m) }
func logWarn(tag, m string)    { log.Printf("%s[%s]%s %s", ColorYellow, tag, ColorReset, m) }
func logError(tag, m string)   { log.Printf("%s[%s]%s %s", ColorRed, tag, ColorReset, m) }

func getHeader(headers, key string) string {
	for _, line := range strings.Split(headers, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), strings.ToLower(key)+": ") {
			return strings.TrimSpace(line[strings.Index(line, ":")+1:])
		}
	}
	return ""
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit { 
		return fmt.Sprintf("%d B", b) 
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
