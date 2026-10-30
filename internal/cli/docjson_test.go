package cli

import "testing"

// spec: CLI
func TestMarkdown(t *testing.T) {
	tests := []struct{ name, body, want string }{
		{"paragraph", "A <name> with_a *star* [x] & #1 ~/a `b` a|b\\c.\n",
			"A \\<name\\> with\\_a \\*star\\* \\[x\\] \\& \\#1 \\~/a \\`b\\` a\\|b\\\\c.\n"},
		{"line starts", "Text:\n  first\n  --set x\n  + y\n  3) z\n",
			"## Text\n\nfirst\n\\--set x\n\\+ y\n3\\) z\n"},
		{"heading", "Intro.\n\nSyntax:\n  A line\n  and more.\n\n  Second.\n",
			"Intro.\n\n## Syntax\n\nA line\nand more.\n\nSecond.\n"},
		{"code", "Example:\n  Text:\n\n    # winch.yaml\n    steps:\n      - name: x\n        file: {}\n",
			"## Example\n\nText:\n\n```\n# winch.yaml\nsteps:\n  - name: x\n    file: {}\n```\n"},
		{"table", "Marks:\n  +  create\n  ~  change\n\n  After.\n",
			"## Marks\n\n```\n+  create\n~  change\n```\n\nAfter.\n"},
		{"table with a list marker", "Marks:\n  +  create\n  -  remove\n  ?  unknown\n",
			"## Marks\n\n```\n+  create\n-  remove\n?  unknown\n```\n"},
		{"list after a paragraph", "Access:\n  First.\n  - a <b>\n    c_d\n  - e\n",
			"## Access\n\nFirst.\n\n- a \\<b\\>\n  c\\_d\n- e\n"},
		{"numbered list", "Port:\n  Steps:\n\n    1. --set x\n    2. y\n",
			"## Port\n\nSteps:\n\n1. \\--set x\n2. y\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := markdown(tt.body); got != tt.want {
				t.Errorf("markdown(%q)\n%s\nwant\n%s", tt.body, got, tt.want)
			}
		})
	}
}
