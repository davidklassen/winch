package run

import (
	"regexp"
	"slices"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/yamlx"
)

// sshdWarnings warns at each step without confirm_access that restarts or
// reloads sshd after an earlier step of its host changed sshd's config.
func (p *Plan) sshdWarnings() []*yamlx.Error {
	var out []*yamlx.Error
	warn := func(pos yamlx.Pos) {
		if !slices.ContainsFunc(out, func(w *yamlx.Error) bool { return w.Pos == pos }) {
			out = append(out, yamlx.Errorf(pos, "sshd loads a changed config without an access check; reload it in a service handler with confirm_access: true"))
		}
	}
	changed := map[string]bool{}
	for _, sp := range p.Stages {
		for _, hp := range sp.Hosts {
			name := hp.Host.Name
			if p.Failed[name] != nil {
				continue
			}
			for _, s := range hp.Steps {
				if s.Handler == nil {
					changed[name] = changed[name] || s.Result.Status == module.Change && slices.ContainsFunc(module.Touches(s.Step.Args), func(t module.Touch) bool { return module.SSHDConfig(t.Path) })
					if changed[name] && s.ThenRuns && sshdThen.MatchString(s.Step.Then) {
						warn(s.Step.Pos)
					}
					continue
				}
				if !changed[name] || !s.Handler.Runs {
					continue
				}
				for _, hs := range s.Handler.Steps {
					if loadsSSHD(hs.Step) {
						warn(hs.Step.Pos)
					}
				}
			}
		}
	}
	return out
}

// sshdThen matches a command that restarts or reloads ssh or sshd:
// systemctl restart ssh, service ssh reload.
var sshdThen = regexp.MustCompile(`(restart|reload)[ \t]+([^\s;&|]+[ \t]+)*sshd?(\.service)?($|[\s;&|)])|(^|[\s;&|(/])sshd?[ \t]+(restart|reload)`)

// loadsSSHD reports whether the handler step st restarts or reloads sshd
// without confirm_access.
func loadsSSHD(st project.Step) bool {
	if sv, ok := st.Args.(*module.Service); ok && (sv.Restarted || sv.Reloaded) && !st.ConfirmAccess {
		return sv.Unit() == "ssh.service" || sv.Unit() == "sshd.service"
	}
	return sshdThen.MatchString(st.Then)
}
