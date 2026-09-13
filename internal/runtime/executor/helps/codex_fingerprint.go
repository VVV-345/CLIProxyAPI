package helps

import (
	"strings"

	"github.com/google/uuid"
)

func CodexFingerprintUUID(seed, kind, value string) string {
	name := strings.Join([]string{
		"cli-proxy-api",
		"codex",
		"fingerprint",
		strings.TrimSpace(kind),
		strings.TrimSpace(seed),
		strings.TrimSpace(value),
	}, ":")
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(name)).String()
}
