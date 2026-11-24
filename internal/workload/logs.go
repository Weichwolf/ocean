package workload

import (
	"slices"
	"strings"
	"unicode/utf8"
)

const MaxLogs = 15 << 10

// RedactLogs drops configured secrets before logs cross the host boundary or
// enter durable metadata. Workload logs are untrusted text and size bounded.
func RedactLogs(logs string, variables []Variable) string {
	var secrets []string
	for _, variable := range variables {
		if variable.SecureValue != nil && *variable.SecureValue != "" {
			secrets = append(secrets, *variable.SecureValue)
		}
	}
	slices.SortFunc(secrets, func(a, b string) int { return len(b) - len(a) })
	for _, secret := range secrets {
		logs = strings.ReplaceAll(logs, secret, "[redacted]")
	}
	if len(logs) > MaxLogs {
		logs = logs[len(logs)-MaxLogs:]
		for logs != "" && !utf8.RuneStart(logs[0]) {
			logs = logs[1:]
		}
	}
	return strings.ToValidUTF8(logs, "?")
}
