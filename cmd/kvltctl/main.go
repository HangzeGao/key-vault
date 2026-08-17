// Command kvltctl is the local, read-only operations client for key-vault.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/kvlt/key-vault/internal/auditchain"
	"github.com/kvlt/key-vault/internal/auth/access"
	"github.com/kvlt/key-vault/internal/operations"
)

const (
	exitReady         = 0
	exitDegraded      = 1
	exitUnreachable   = 2
	exitAuditCorrupt  = 3
	exitConfiguration = 4
)

type client struct {
	baseURL, token string
	http           *http.Client
}

func main() { os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr)) }

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	jsonRequested := false
	filtered := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == "--json" {
			jsonRequested = true
			continue
		}
		filtered = append(filtered, arg)
	}
	args = filtered
	root := flag.NewFlagSet("kvltctl", flag.ContinueOnError)
	root.SetOutput(stderr)
	addr := root.String("addr", envOr("KVLT_OPS_ADDR", "http://127.0.0.1:8080"), "loopback operations URL")
	tokenFile := root.String("token-file", os.Getenv("KVLT_OPS_TOKEN_FILE"), "0600 file containing the operations token")
	caFile := root.String("ca-file", os.Getenv("KVLT_OPS_CA_FILE"), "pinned TLS server certificate")
	timeout := root.Duration("timeout", 5*time.Second, "request timeout")
	if err := root.Parse(args); err != nil {
		return exitConfiguration
	}
	if root.NArg() == 0 {
		usage(stderr)
		return exitConfiguration
	}
	parsed, err := url.Parse(*addr)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		fmt.Fprintln(stderr, "configuration error: --addr must be an http(s) origin without credentials or path")
		return exitConfiguration
	}
	host := parsed.Hostname()
	if host != "localhost" && (net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback()) {
		fmt.Fprintln(stderr, "configuration error: --addr must use an explicit loopback host")
		return exitConfiguration
	}
	transport, err := clientTransport(parsed.Scheme, *caFile)
	if err != nil {
		fmt.Fprintf(stderr, "configuration error: %v\n", err)
		return exitConfiguration
	}
	token, err := readToken(*tokenFile)
	if err != nil {
		fmt.Fprintf(stderr, "configuration error: %v\n", err)
		return exitConfiguration
	}
	c := client{baseURL: strings.TrimRight(*addr, "/"), token: token, http: &http.Client{Timeout: *timeout,
		Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}}
	command := root.Arg(0)
	switch command {
	case "status":
		return statusCommand(ctx, c, jsonRequested, stdout, stderr)
	case "doctor":
		return doctorCommand(ctx, c, jsonRequested, stdout, stderr)
	case "audit":
		return auditCommand(ctx, c, root.Args()[1:], jsonRequested, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", command)
		usage(stderr)
		return exitConfiguration
	}
}

func statusCommand(ctx context.Context, c client, asJSON bool, stdout, stderr io.Writer) int {
	var snapshot operations.Snapshot
	if code := c.get(ctx, "/ops/v1/status", &snapshot, stderr); code != exitReady {
		return code
	}
	if asJSON {
		writeJSON(stdout, snapshot)
	} else {
		fmt.Fprintf(stdout, "%s ready=%t uptime=%ds tc=%s downlink_generation=%d audit_events=%d\n",
			snapshot.Status, snapshot.Ready, snapshot.UptimeSeconds, snapshot.Checks["tc"].Status,
			snapshot.Downlink.CurrentGeneration, snapshot.Database.AuditEvents)
		fmt.Fprintf(stdout, "access_rejections source_ip=%d token=%d plane=%d rate_limited=%d\n",
			snapshot.AccessRejections.SourceIPRejected, snapshot.AccessRejections.TokenRejected,
			snapshot.AccessRejections.PlaneRejected, snapshot.AccessRejections.RateLimited)
		for _, warning := range snapshot.Warnings {
			fmt.Fprintf(stdout, "warning: %s\n", warning)
		}
	}
	if snapshot.Ready {
		return exitReady
	}
	return exitDegraded
}

func doctorCommand(ctx context.Context, c client, asJSON bool, stdout, stderr io.Writer) int {
	var snapshot operations.Snapshot
	if code := c.get(ctx, "/ops/v1/status", &snapshot, stderr); code != exitReady {
		return code
	}
	var verify struct {
		Results []*auditchain.VerifyResult `json:"results"`
	}
	if code := c.get(ctx, "/ops/v1/audit/verify", &verify, stderr); code != exitReady {
		return code
	}
	intact := true
	for _, value := range verify.Results {
		if value == nil || !value.Intact {
			intact = false
		}
	}
	if asJSON {
		writeJSON(stdout, map[string]any{"status": snapshot, "audit": verify, "audit_intact": intact})
	} else {
		fmt.Fprintf(stdout, "service=%s audit_intact=%t checks=%d\n", snapshot.Status, intact, len(snapshot.Checks))
	}
	if !intact {
		return exitAuditCorrupt
	}
	if !snapshot.Ready {
		return exitDegraded
	}
	return exitReady
}

func auditCommand(ctx context.Context, c client, args []string, inheritedJSON bool, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "audit requires tail or verify")
		return exitConfiguration
	}
	switch args[0] {
	case "tail":
		fs := flag.NewFlagSet("audit tail", flag.ContinueOnError)
		fs.SetOutput(stderr)
		limit := fs.Int("limit", 50, "number of events (1..500)")
		asJSON := fs.Bool("json", inheritedJSON, "emit JSON")
		if err := fs.Parse(args[1:]); err != nil || *limit < 1 || *limit > 500 {
			return exitConfiguration
		}
		var value struct {
			Events []json.RawMessage `json:"events"`
			Total  int               `json:"total"`
		}
		if code := c.get(ctx, "/ops/v1/audit/events?limit="+strconv.Itoa(*limit), &value, stderr); code != exitReady {
			return code
		}
		if *asJSON {
			writeJSON(stdout, value)
		} else {
			for _, event := range value.Events {
				fmt.Fprintln(stdout, string(event))
			}
		}
		return exitReady
	case "verify":
		fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
		fs.SetOutput(stderr)
		asJSON := fs.Bool("json", inheritedJSON, "emit JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return exitConfiguration
		}
		var value json.RawMessage
		if code := c.get(ctx, "/ops/v1/audit/verify", &value, stderr); code != exitReady {
			return code
		}
		intact := auditIntact(value)
		if *asJSON {
			fmt.Fprintln(stdout, string(value))
		} else {
			fmt.Fprintf(stdout, "audit_intact=%t\n", intact)
		}
		if intact {
			return exitReady
		}
		return exitAuditCorrupt
	default:
		fmt.Fprintf(stderr, "unknown audit command %q\n", args[0])
		return exitConfiguration
	}
}

func (c client) get(ctx context.Context, path string, output any, stderr io.Writer) int {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		fmt.Fprintln(stderr, "request error")
		return exitConfiguration
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		fmt.Fprintf(stderr, "operations endpoint unreachable: %v\n", err)
		return exitUnreachable
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		fmt.Fprintln(stderr, "operations credential rejected")
		return exitConfiguration
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(stderr, "operations endpoint returned %s\n", resp.Status)
		return exitDegraded
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 2<<20))
	if err := decoder.Decode(output); err != nil {
		fmt.Fprintln(stderr, "invalid operations response")
		return exitDegraded
	}
	return exitReady
}

func readToken(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("--token-file or KVLT_OPS_TOKEN_FILE is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("token file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("token file must be a regular non-symlink file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("token file permissions must be 0600 or stricter")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("token file: %w", err)
	}
	token := strings.TrimSuffix(string(content), "\n")
	if strings.ContainsAny(token, " \t\r\n") || access.ValidateToken(token) != nil {
		return "", errors.New("token file must contain one canonical 256-bit base64url token")
	}
	return token, nil
}

func clientTransport(scheme, caFile string) (http.RoundTripper, error) {
	if scheme == "http" {
		if strings.TrimSpace(caFile) != "" {
			return nil, errors.New("--ca-file is only valid with https")
		}
		return http.DefaultTransport, nil
	}
	if strings.TrimSpace(caFile) == "" {
		return nil, errors.New("https requires --ca-file or KVLT_OPS_CA_FILE")
	}
	info, err := os.Lstat(caFile)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("CA file must be a readable regular non-symlink file")
	}
	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("CA file contains no valid certificate")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	return transport, nil
}

func auditIntact(raw []byte) bool {
	var value struct {
		Results []*auditchain.VerifyResult `json:"results"`
	}
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	for _, result := range value.Results {
		if result == nil || !result.Intact {
			return false
		}
	}
	return true
}

func writeJSON(w io.Writer, value any) {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(value)
}
func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: kvltctl [--addr URL] --token-file PATH [--ca-file CERT] [--json] {status|doctor|audit tail|audit verify}")
}
