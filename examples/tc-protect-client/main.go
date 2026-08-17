// Command tc-protect-client demonstrates the complete Data-plane client
// contract: pinned TLS 1.3, a protected fixed Data token, and a complete TC
// plaintext frame in / protected frame out.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/kvlt/key-vault/internal/auth/access"
)

type protectRequest struct {
	Frame string `json:"frame"`
}

type protectResponse struct {
	ProtectedFrame string `json:"protected_frame"`
}

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("tc-protect-client", flag.ContinueOnError)
	addr := flags.String("addr", "", "Data-plane HTTPS origin")
	caFile := flags.String("ca-file", "", "pinned server certificate or CA")
	tokenFile := flags.String("token-file", "", "0600 Data token file")
	frameFile := flags.String("frame-file", "", "complete plaintext TC frame")
	outputFile := flags.String("output-file", "", "new protected TC frame file")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return errors.New("usage: tc-protect-client --addr https://HOST:PORT --ca-file CERT --token-file FILE --frame-file FILE --output-file FILE")
	}
	origin, err := url.Parse(*addr)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return errors.New("--addr must be one HTTPS origin without credentials, path, query, or fragment")
	}
	if *frameFile == "" || *outputFile == "" {
		return errors.New("--frame-file and --output-file are required")
	}
	token, err := readToken(*tokenFile)
	if err != nil {
		return err
	}
	roots, err := readRoots(*caFile)
	if err != nil {
		return err
	}
	frame, err := os.ReadFile(*frameFile)
	if err != nil || len(frame) == 0 {
		return errors.New("read non-empty TC frame failed")
	}
	body, err := json.Marshal(protectRequest{Frame: base64.StdEncoding.EncodeToString(frame)})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, *addr+"/api/v1/tc:protect", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	client := &http.Client{Timeout: 15 * time.Second, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("protect request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		return fmt.Errorf("protect request returned %s", response.Status)
	}
	var result protectResponse
	decoder := json.NewDecoder(io.LimitReader(response.Body, 2<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return errors.New("invalid protect response")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("protect response contains trailing data")
	}
	protected, err := base64.StdEncoding.DecodeString(result.ProtectedFrame)
	if err != nil || len(protected) == 0 {
		return errors.New("invalid protected frame")
	}
	file, err := os.OpenFile(*outputFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	if _, err = file.Write(protected); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		_ = os.Remove(*outputFile)
		return fmt.Errorf("write output file: %w", err)
	}
	if closeErr != nil {
		_ = os.Remove(*outputFile)
		return fmt.Errorf("close output file: %w", closeErr)
	}
	return nil
}

func readToken(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("token file must be a readable regular non-symlink file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("token file permissions must be 0600 or stricter")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", errors.New("read token file failed")
	}
	token := strings.TrimSuffix(string(raw), "\n")
	if strings.ContainsAny(token, " \t\r\n") || access.ValidateToken(token) != nil {
		return "", errors.New("token file must contain one canonical 256-bit base64url token")
	}
	return token, nil
}

func readRoots(path string) (*x509.CertPool, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("CA file must be a readable regular non-symlink file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("read CA file failed")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(raw) {
		return nil, errors.New("CA file contains no valid certificate")
	}
	return roots, nil
}
