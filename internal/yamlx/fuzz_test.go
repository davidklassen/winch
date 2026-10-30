package yamlx

import (
	"errors"
	"testing"
)

// spec: YAML
func FuzzDecode(f *testing.F) {
	for _, tt := range decodeCases {
		f.Add(tt.yaml)
	}
	f.Fuzz(func(t *testing.T, src string) {
		n, err := Parse("test.yaml", []byte(src))
		if err == nil {
			err = Decode(n, &testDoc{})
		}
		checkPositions(t, err)
	})
}

// checkPositions fails when an error that err joins does not name a file, a
// line, and a column.
func checkPositions(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		for _, e := range j.Unwrap() {
			checkPositions(t, e)
		}
		return
	}
	var ye *Error
	if !errors.As(err, &ye) || ye.Pos.File == "" || ye.Pos.Line < 1 || ye.Pos.Col < 1 {
		t.Errorf("the error %q names no file, line, and column", err)
	}
}
