package run

import (
	"slices"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/yamlx"
)

// publicWarnings warns at each step that writes a secret where other users of
// the host can read it: a line into a file that others can read, a user
// comment, and a debconf answer that is not a password. A value holds a
// secret when its masked copy differs.
func (p *Plan) publicWarnings() []*yamlx.Error {
	var out []*yamlx.Error
	check := func(s Planned) {
		msg := ""
		switch a := s.Step.Args.(type) {
		case *module.Line:
			if s.Result.OthersRead && s.Step.Shown().Args.(*module.Line).Line != a.Line {
				msg = "the file holds a secret and others can read it; write the secret to a file with mode 0600 in a file step"
			}
		case *module.User:
			if s.Step.Shown().Args.(*module.User).Comment != a.Comment {
				msg = "the user comment holds a secret, and every user of the host can read /etc/passwd"
			}
		case *module.Debconf:
			if a.Type != "password" && s.Step.Shown().Args.(*module.Debconf).Value != a.Value {
				msg = "debconf keeps the answer in /var/cache/debconf/config.dat, which every user of the host can read; only a password answer goes to a root-only file"
			}
		}
		if msg != "" && !slices.ContainsFunc(out, func(w *yamlx.Error) bool { return w.Pos == s.Step.Pos && w.Msg == msg }) {
			out = append(out, yamlx.Errorf(s.Step.Pos, "%s", msg))
		}
	}
	for _, sp := range p.Stages {
		for _, hp := range sp.Hosts {
			if p.Failed[hp.Host.Name] != nil {
				continue
			}
			for _, s := range hp.Steps {
				check(s)
			}
		}
	}
	return out
}
