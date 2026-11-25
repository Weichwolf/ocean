package desktopgateway

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Weichwolf/ocean/internal/arm"
)

const maxInstructionBytes = 4 << 20

func readInstruction(r *bufio.Reader) ([]string, error) {
	var fields []string
	remaining := maxInstructionBytes
	for len(fields) < 256 {
		size := 0
		for digits := 0; ; digits++ {
			b, err := r.ReadByte()
			if err != nil {
				return nil, err
			}
			if b == '.' && digits > 0 {
				break
			}
			if b < '0' || b > '9' || digits >= 7 {
				return nil, errors.New("invalid Guacamole instruction length")
			}
			size = size*10 + int(b-'0')
		}
		if size > remaining {
			return nil, errors.New("Guacamole instruction exceeds its size limit")
		}
		var value strings.Builder
		for range size {
			char, bytes, err := r.ReadRune()
			if err != nil {
				return nil, err
			}
			if char == utf8.RuneError && bytes == 1 || bytes > remaining {
				return nil, errors.New("invalid or oversized Guacamole instruction")
			}
			remaining -= bytes
			value.WriteRune(char)
		}
		fields = append(fields, value.String())
		delimiter, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		switch delimiter {
		case ';':
			return fields, nil
		case ',':
		default:
			return nil, errors.New("invalid Guacamole instruction delimiter")
		}
	}
	return nil, errors.New("Guacamole instruction has too many fields")
}

func encodeInstruction(fields ...string) string {
	var result strings.Builder
	for i, value := range fields {
		if i > 0 {
			result.WriteByte(',')
		}
		result.WriteString(strconv.Itoa(utf8.RuneCountInString(value)))
		result.WriteByte('.')
		result.WriteString(value)
	}
	result.WriteByte(';')
	return result.String()
}

func writeInstruction(w io.Writer, fields ...string) error {
	_, err := io.WriteString(w, encodeInstruction(fields...))
	return err
}

func openGuacamole(conn net.Conn, launch arm.DesktopLaunch, fingerprint string) (*bufio.Reader, error) {
	reader := bufio.NewReader(conn)
	if err := writeInstruction(conn, "select", "rdp"); err != nil {
		return nil, err
	}
	args, err := readInstruction(reader)
	if err != nil {
		return nil, err
	}
	if len(args) < 2 || args[0] != "args" || args[1] != "VERSION_1_5_0" {
		return nil, errors.New("unexpected Guacamole protocol version")
	}
	options := map[string]string{
		"hostname": launch.PrivateIP.String(), "port": "3389", "username": launch.User, "password": launch.Credential,
		"security": "tls", "cert-fingerprints": "sha256:" + fingerprint,
		"disable-copy": "true", "disable-paste": "true", "enable-drive": "false", "enable-printing": "false",
	}
	connect := append(make([]string, 0, len(args)), "connect", args[1])
	for _, name := range args[2:] {
		connect = append(connect, options[name])
		delete(options, name)
	}
	for _, required := range []string{"hostname", "port", "username", "password", "security", "cert-fingerprints", "disable-copy", "disable-paste"} {
		if _, missing := options[required]; missing {
			return nil, fmt.Errorf("guacd does not support required RDP option %s", required)
		}
	}
	for _, fields := range [][]string{
		{"size", "1280", "720", "96"}, {"audio"}, {"video"}, {"image", "image/png", "image/jpeg"}, {"timezone", "UTC"},
		connect,
	} {
		if err := writeInstruction(conn, fields...); err != nil {
			return nil, err
		}
	}
	reply, err := readInstruction(reader)
	if err != nil {
		return nil, err
	}
	if len(reply) != 2 || reply[0] != "ready" || reply[1] == "" {
		return nil, errors.New("guacd failed to initialize the desktop tunnel")
	}
	return reader, nil
}
