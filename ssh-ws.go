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
 * Project      : GO-TUNNEL PRO (SSH-WS & UDPGW)
 * Developers   : Risqi Nur Fadhilah
 * Tester       : Rerechan02
 * Version      : v1.1-Stable
 * License      : MIT License
 * ----------------------------------------------------------------------------
 *
 * CMD Compile:
 * CGO_ENABLED=0 go build -ldflags "-s -w -X 'main.Credits=Risqi Nur Fadhilah' -X 'main.Version=v1.1-Stable'" -o ssh-ws
 *
 * Requirements:
 * - Debian 11 / Ubuntu 22.04+
 * - Go version 1.22.0 or higher
 */

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mukswilly/udpgw"
)

var (
	Version = "v1.0-Stable"
	Credits = "Risqi Nur Fadhilah"
)

// This Colors & UI
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
	ColorGray   = "\033[90m"
	ColorPurple = "\033[35m"
	ColorBlue   = "\033[34m"
	
	PayloadResponse = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
)

type Config struct {
	BindAddr     string
	Port         int
	Password     string
	FallbackAddr string
	LogFile      string
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

func main() {
	cfg := setupFlags()
	
	setupLogger(cfg.LogFile)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	printProxyBanner()

	go func() {
		// Config untuk BadVPN
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

	// Run fake proxy websocket
	serverAddr := fmt.Sprintf("%s:%d", cfg.BindAddr, cfg.Port)
	listener, err := net.Listen("tcp", serverAddr)
	if err != nil {
		logError("CORE", fmt.Sprintf("Failed to bind %s: %v", serverAddr, err))
		os.Exit(1)
	}

	go func() {
		logInfo("SSHWS", fmt.Sprintf("Listening on %s%s%s", ColorCyan, serverAddr, ColorReset))
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

	// Shutdown Proxy
	<-ctx.Done()
	fmt.Println("\n" + ColorYellow + " [!] Shutdown signal received. Closing all connections..." + ColorReset)
	listener.Close()
	time.Sleep(1 * time.Second)
	logInfo("SYSTEM", "Server halted successfully.")
}

func handleConnection(clientConn net.Conn, cfg Config) {
	defer clientConn.Close()

	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, err := clientConn.Read(buf)
	if err != nil { return }
	clientConn.SetReadDeadline(time.Time{})

	rawHeaders := string(buf[:n])
	targetHost := getHeader(rawHeaders, "X-Real-Host")
	if targetHost == "" { targetHost = cfg.FallbackAddr }

	authPass := getHeader(rawHeaders, "X-Pass")
	if cfg.Password != "" && authPass != cfg.Password {
		logWarn("AUTH", fmt.Sprintf("Unauthorized access from %s", clientConn.RemoteAddr()))
		clientConn.Write([]byte("HTTP/1.1 401 Unauthorized\r\n\r\n"))
		return
	}

	if !strings.Contains(targetHost, ":") { targetHost += ":22" }

	targetConn, err := net.DialTimeout("tcp", targetHost, 10*time.Second)
	if err != nil {
		logError("TUNNEL", fmt.Sprintf("Failed to reach target %s", targetHost))
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer targetConn.Close()

	logSuccess("CONN", fmt.Sprintf("%s -> %s", clientConn.RemoteAddr(), targetHost))
	clientConn.Write([]byte(PayloadResponse))

	// Data Transfer & Monitoring TX/RX
	doTransfer(clientConn, targetConn, targetHost)
}

func doTransfer(client, target net.Conn, targetName string) {
	var tx, rx int64
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
				currTx := atomic.LoadInt64(&tx)
				currRx := atomic.LoadInt64(&rx)
				if currTx > 0 || currRx > 0 {
					log.Printf("%s[MON] %s | TX: %s | RX: %s%s", ColorPurple, targetName, formatBytes(currTx), formatBytes(currRx), ColorReset)
				}
			}
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(WriteCounter{target, &tx}, client)
		if t, ok := target.(*net.TCPConn); ok { t.CloseWrite() }
	}()
	go func() {
		defer wg.Done()
		io.Copy(WriteCounter{client, &rx}, target)
		if c, ok := client.(*net.TCPConn); ok { c.CloseWrite() }
	}()

	wg.Wait()
	stopMonitor <- true
	log.Printf("%s[END] %s | Total TX: %s | RX: %s%s", ColorGray, targetName, formatBytes(tx), formatBytes(rx), ColorReset)
}

func setupFlags() Config {
	c := Config{}
	var logF1, logF2, logF3 string

	flag.StringVar(&c.BindAddr, "b", "0.0.0.0", "Bind Address")
	flag.IntVar(&c.Port, "p", 8080, "Port server")
	flag.StringVar(&c.Password, "a", "", "Auth Password")
	flag.StringVar(&c.FallbackAddr, "t", "127.0.0.1:22", "Default Target")
	
	flag.StringVar(&logF1, "l", "", "Log file path")
	flag.StringVar(&logF2, "log", "", "Log file path")
	flag.StringVar(&logF3, "logs", "", "Log file path")
	
	flag.Parse()

	if logF1 != "" { c.LogFile = logF1 } else if logF2 != "" { c.LogFile = logF2 } else { c.LogFile = logF3 }
	
	return c
}

func setupLogger(path string) {
	writers := []io.Writer{os.Stdout}
	if path != "" {
		_ = os.MkdirAll(filepath.Dir(path), 0755)
		file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil { writers = append(writers, file) }
	}
	log.SetOutput(io.MultiWriter(writers...))
	log.SetFlags(log.Ldate | log.Ltime)
}

func printProxyBanner() {
	fmt.Print(ColorCyan)
	fmt.Println(` ╔════════════════════════════════════════════════════════╗`)
	fmt.Println(` ║    ___  ___  ____  _  ____  __                         `)
	fmt.Println(` ║   / _ \/ _ \/ __ \| |/ /\ \/ /                         `)
	fmt.Println(` ║  / ___/ , _/ /_/ /  |   \  /                           `)
	fmt.Println(` ║ /_/  /_/|_|\____/_/|_|   /_/                           `)
	fmt.Println(` ║                                                        `)
	fmt.Printf(" ║  %s  VERSION   : %-37s %s\n", ColorGray, Version, ColorCyan)
	fmt.Printf(" ║  %s  DEVELOPER : %-37s %s\n", ColorGray, Credits, ColorCyan)
	fmt.Println(` ╚════════════════════════════════════════════════════════╝`)
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
	if b < unit { return fmt.Sprintf("%d B", b) }
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
