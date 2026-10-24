package module

import (
	"strings"
	"testing"
)

func TestRunErrorEndsWithStderr(t *testing.T) {
	_, err := run(t.Context(), nil, "sh", "-c", "seq 20; echo 'E: the cause' >&2; exit 1")
	if err == nil || !strings.HasSuffix(err.Error(), "E: the cause") {
		t.Fatalf("error = %v, want it to end with the stderr line", err)
	}
}
