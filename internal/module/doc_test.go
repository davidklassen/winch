package module

import "testing"

// spec: CLI
func TestReferenceText(t *testing.T) {
	var check func(t *testing.T, prefix string, keys []Key)
	check = func(t *testing.T, prefix string, keys []Key) {
		for _, k := range keys {
			if k.Text == "" {
				t.Errorf("key %s%s has no text", prefix, k.Name)
			}
			check(t, prefix+k.Name+".", k.Keys)
		}
	}
	for _, name := range Names() {
		d, _ := Reference(name)
		if d.Text == "" {
			t.Errorf("module %s has no text", name)
		}
		if len(d.Keys) == 0 {
			t.Errorf("module %s has no keys", name)
		}
		check(t, name+".", d.Keys)
	}
}
