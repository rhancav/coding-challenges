package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var blacklistedDomains []string
var requestCount int
var blockedRequestCount int
var mutex sync.Mutex

func main() {
	log.Println("Starting proxy server...")

	loadBlacklistedDomains("blacklisted_domains.txt")

	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatalf("Failed to start listener: %v", err)
	}
	log.Println("Listening on :8080")

	go logRequestCount()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	bufConn := bufio.NewReader(conn)
	req, err := http.ReadRequest(bufConn)
	if err != nil {
		log.Printf("Failed to read request: %v", err)
		return
	}

	mutex.Lock()
	requestCount++
	mutex.Unlock()

	if domainBlacklisted(req.Host) {
		mutex.Lock()
		blockedRequestCount++
		mutex.Unlock()
		writeHTTPError(conn, http.StatusForbidden, "Forbidden domain")
		log.Printf("Domain %s is forbidden", req.Host)
		return
	}

	if req.Method == http.MethodConnect {
		handleHTTPS(conn, req)
	} else {
		handleHTTP(conn, req)
	}
}

func handleHTTP(conn net.Conn, req *http.Request) {
	httpClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	newReq, err := http.NewRequest(req.Method, req.RequestURI, req.Body)
	if err != nil {
		writeHTTPError(conn, http.StatusInternalServerError, "Error creating new request")
		log.Printf("Error creating new request: %v", err)
		return
	}

	newReq.Header = req.Header.Clone()
	clientIP := conn.RemoteAddr().(*net.TCPAddr).IP.String()
	if existingXFF := req.Header.Get("X-Forwarded-For"); existingXFF != "" {
		newReq.Header.Set("X-Forwarded-For", existingXFF+", "+clientIP)
	} else {
		newReq.Header.Set("X-Forwarded-For", clientIP)
	}

	resp, err := httpClient.Do(newReq)
	if err != nil {
		writeHTTPError(conn, http.StatusInternalServerError, "Error performing request")
		log.Printf("Error performing request: %v", err)
		return
	}
	defer resp.Body.Close()

	err = resp.Write(conn)
	if err != nil {
		log.Printf("Error writing response: %v", err)
	}
	log.Printf("Received request %s %s from client %s: Status %d", req.Method, req.URL.String(), conn.RemoteAddr(), resp.StatusCode)
}

func handleHTTPS(conn net.Conn, req *http.Request) {
	destConn, err := net.Dial("tcp", req.Host)
	if err != nil {
		writeHTTPError(conn, http.StatusServiceUnavailable, "Unable to reach destination server")
		log.Printf("Unable to reach destination server: %v", err)
		return
	}
	defer destConn.Close()

	_, err = fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	if err != nil {
		log.Printf("Error writing connection established response: %v", err)
		return
	}

	log.Printf("Received request %s %s from client %s and successfully established tunnel", req.Method, "https:"+req.URL.String(), conn.RemoteAddr())
	go transferWithLogging(destConn, conn)
	transferWithLogging(conn, destConn)
}

func transferWithLogging(destination io.Writer, source io.Reader) {
	_, err := io.Copy(destination, source)
	if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
		log.Printf("Error while transferring data: %v", err)
	}
}

func writeHTTPError(conn net.Conn, statusCode int, statusText string) {
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: %d\r\nContent-Type: text/plain\r\n\r\n%s", statusCode, statusText, len(statusText), statusText)
	conn.Write([]byte(response))
}

func domainBlacklisted(domain string) bool {
	for _, blacklistedDomain := range blacklistedDomains {
		if strings.Contains(domain, blacklistedDomain) {
			return true
		}
	}
	return false
}

func loadBlacklistedDomains(filePath string) {
	blacklistedDomainsFile, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer blacklistedDomainsFile.Close()

	bytes, err := io.ReadAll(blacklistedDomainsFile)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	blacklistedDomains = strings.Split(string(bytes), "\n")
}

func logRequestCount() {
	ticker := time.NewTicker(10 * time.Second)
	for range ticker.C {
		log.Printf("Proxied requests count: %d Total Blocked: %d", requestCount, blockedRequestCount)
	}
}
