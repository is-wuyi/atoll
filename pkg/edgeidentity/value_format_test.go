package edgeidentity

import (
	"fmt"
	"strings"
	"testing"
)

func TestCopiedIdentityFormattingIsRedacted(t *testing.T) {
	_, id := validKeyBlob(t, t.TempDir())
	for _, value := range []any{*id, struct{ Identity Identity }{*id}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%x", "%X"} {
			shown := fmt.Sprintf(verb, value)
			if strings.Contains(shown, "priv:") || strings.Contains(shown, "priv=") {
				t.Fatalf("copied identity exposed private fields with %s", verb)
			}
		}
	}
}
