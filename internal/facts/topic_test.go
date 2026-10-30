package facts

import "testing"

// spec: Remote execution/Facts
func TestTopicText(t *testing.T) {
	topic := Topic()
	if topic.Text == "" || topic.Body == "" {
		t.Error("the topic has no text")
	}
	for _, k := range topic.Keys {
		for _, k := range append(k.Keys, k) {
			if k.Text == "" {
				t.Errorf("fact %s has no text", k.Name)
			}
			if k.Default != "" {
				t.Errorf("fact %s has the default %q", k.Name, k.Default)
			}
		}
	}
}
