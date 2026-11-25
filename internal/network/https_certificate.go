package network

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"
)

const maximumIngressBundle = 64 << 10

var ingressDecoders = make(chan struct{}, 4)

// HTTPSCertificate carries the public identity and private PEM bundle from a PFX.
type HTTPSCertificate struct {
	Hostname          string
	PublicCertificate []byte
	Bundle            []byte `json:"-"`
}

// DecodeHTTPSCertificate reads an uploaded PKCS#12 using OpenSSL. It receives
// both inputs over file descriptors and keeps diagnostic output private.
func DecodeHTTPSCertificate(ctx context.Context, pfx []byte, password string) (HTTPSCertificate, error) {
	var result HTTPSCertificate
	if len(pfx) == 0 || len(pfx) > 48<<10 || password == "" || len(password) > 256 || strings.ContainsAny(password, "\r\n\x00") {
		return result, errors.New("invalid Application Gateway certificate input")
	}
	select {
	case ingressDecoders <- struct{}{}:
		defer func() { <-ingressDecoders }()
	case <-ctx.Done():
		return result, ctx.Err()
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return result, err
	}
	defer func() { _ = reader.Close() }()
	_, err = io.WriteString(writer, password+"\n")
	if err := errors.Join(err, writer.Close()); err != nil {
		return result, err
	}
	command := exec.CommandContext(ctx, "/usr/bin/openssl", "pkcs12", "-noenc", "-passin", "fd:3")
	command.Stdin = bytes.NewReader(pfx)
	command.ExtraFiles = []*os.File{reader}
	output, err := command.StdoutPipe()
	if err != nil {
		return result, err
	}
	if err := command.Start(); err != nil {
		return result, err
	}
	decoded, readErr := io.ReadAll(io.LimitReader(output, maximumIngressBundle+1))
	if readErr != nil || len(decoded) > maximumIngressBundle {
		_ = command.Process.Kill()
	}
	if err := command.Wait(); err != nil || readErr != nil || len(decoded) > maximumIngressBundle {
		return result, errors.New("unable to decode the Application Gateway certificate")
	}
	var bundle bytes.Buffer
	keyCount := 0
	for block, rest := pem.Decode(decoded); block != nil; block, rest = pem.Decode(rest) {
		switch block.Type {
		case "CERTIFICATE":
		case "PRIVATE KEY":
			keyCount++
		default:
			return result, errors.New("the Application Gateway certificate bundle contains unsupported material")
		}
		if err := pem.Encode(&bundle, block); err != nil {
			return result, err
		}
	}
	if keyCount != 1 {
		return result, errors.New("the Application Gateway certificate must contain one private key")
	}
	leaf, err := ingressCertificateLeaf(bundle.Bytes())
	if err != nil {
		return result, err
	}
	if len(leaf.DNSNames) != 1 || !validIngressHostname(strings.ToLower(leaf.DNSNames[0])) {
		return result, errors.New("the certificate must identify a single HTTPS DNS name")
	}
	return HTTPSCertificate{Hostname: strings.ToLower(leaf.DNSNames[0]), PublicCertificate: leaf.Raw, Bundle: bundle.Bytes()}, nil
}

func ingressCertificateLeaf(bundle []byte) (*x509.Certificate, error) {
	keypair, err := tls.X509KeyPair(bundle, bundle)
	if err != nil {
		return nil, errors.New("the TLS bundle must contain a matching certificate and private key")
	}
	leaf, err := x509.ParseCertificate(keypair.Certificate[0])
	if err != nil {
		return nil, errors.New("the ingress certificate is invalid")
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || len(leaf.ExtKeyUsage) != 0 &&
		!slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return nil, errors.New("the certificate must be valid for TLS server authentication")
	}
	return leaf, nil
}
