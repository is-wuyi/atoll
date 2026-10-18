package contentcrypto

import (
	"fmt"
	"strings"
	"testing"
)

func TestCopiedKeyFormattingIsRedacted(t *testing.T) {
	dek := mustDEK(t)
	kek := mustKEK(t, "copied-key")
	for _, value := range []any{*dek, *kek, struct {
		D DEK
		K KEK
	}{*dek, *kek}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%x", "%X"} {
			shown := fmt.Sprintf(verb, value)
			if strings.Contains(shown, "key:") || strings.Contains(shown, "key=") ||
				strings.Contains(shown, fmt.Sprintf("%x", dek[:])) || strings.Contains(shown, fmt.Sprintf("%X", dek[:])) ||
				!strings.Contains(shown, "32B") {
				t.Fatalf("copied key was not redacted with %s", verb)
			}
		}
	}
}
