package run

import (
	"regexp"
	"slices"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/yamlx"
)

// sshdWarnings warns at each step without confirm_access that loads sshd while
// sshd's config has a change that no access check tested. It also warns at
// each change of sshd's config that no later step loads, or that a guarded
// load loads but its rollback cannot put back.
func (p *Plan) sshdWarnings() []*yamlx.Error {
	var out []*yamlx.Error
	warn := func(pos yamlx.Pos, msg string) {
		if !slices.ContainsFunc(out, func(w *yamlx.Error) bool { return w.Pos == pos && w.Msg == msg }) {
			out = append(out, yamlx.Errorf(pos, "%s", msg))
		}
	}
	const (
		unguarded = "sshd loads a changed config without an access check; reload it in a service step with on_change and confirm_access: true"
		untested  = "sshd's config changes, and no step reloads sshd with confirm_access: true; the new config loads untested at the next restart"
	)
	type change struct {
		host   string
		pos    yamlx.Pos
		stores []string
	}
	var pending []change
	for _, sp := range p.Stages {
		for _, hp := range sp.Hosts {
			name := hp.Host.Name
			if p.Failed[name] != nil {
				continue
			}
			for _, s := range hp.Steps {
				if (s.Result.Status == module.Change || s.Result.Status == module.Unknown) && slices.ContainsFunc(module.Touches(s.Step.Args), func(t module.Touch) bool { return module.SSHDConfig(t.Path) }) && !slices.Contains(s.Result.Changes, module.SSHSocketRestart) {
					pending = append(pending, change{name, s.Step.Pos, stores(s)})
				}
				switch {
				case s.Acts && s.LoadsSSHD && s.Step.ConfirmAccess:
					pending = slices.DeleteFunc(pending, func(c change) bool { return c.host == name && slices.Contains(c.stores, s.Record.Store()) })
				case s.Acts && s.LoadsSSHD, s.ThenRuns && sshdThen.MatchString(s.Step.Then):
					before := len(pending)
					pending = slices.DeleteFunc(pending, func(c change) bool { return c.host == name })
					if len(pending) != before {
						warn(s.Step.Pos, unguarded)
					}
				}
			}
		}
	}
	for _, c := range pending {
		warn(c.pos, untested)
	}
	return out
}

// stores returns the rollback stores that keep the old state of the step p,
// as guard sends them to the helper.
func stores(p Planned) []string {
	var out []string
	for _, g := range p.Guarded {
		out = append(out, g.Store())
	}
	return append(out, p.SSHD...)
}

// sshdStores sets LoadsSSHD on each step that loads sshd, and SSHD on each step
// that changes sshd's config. A guarded load of sshd loads the files of every
// earlier step, not only those of its own store. A step with on_change that
// the plan does not expect to act tests nothing: the helper would put back its
// store at the end of the session.
func (p *Plan) sshdStores() {
	steps := map[string][]*Planned{}
	socketOff := map[string]bool{}
	for _, sp := range p.Stages {
		for _, hp := range sp.Hosts {
			name := hp.Host.Name
			for i := range hp.Steps {
				s := &hp.Steps[i]
				s.LoadsSSHD = loadsSSHD(*s, socketOff[name])
				socketOff[name] = socketOff[name] || stopsSocket(*s)
				steps[name] = append(steps[name], s)
			}
		}
	}
	for _, refs := range steps {
		var later []string
		for _, r := range slices.Backward(refs) {
			if slices.ContainsFunc(module.Touches(r.Step.Args), func(t module.Touch) bool { return module.SSHDConfig(t.Path) }) {
				r.SSHD = slices.Clone(later)
			}
			if store := r.Record.Store(); r.Acts && r.LoadsSSHD && r.Step.ConfirmAccess && !slices.Contains(later, store) {
				later = append(later, store)
			}
		}
	}
}

// sshdThen matches a command that restarts or reloads ssh or sshd, or that
// starts or restarts ssh.socket: systemctl restart ssh, service ssh reload,
// systemctl start ssh.socket.
var sshdThen = regexp.MustCompile(`(restart|reload)[ \t]+([^\s;&|]+[ \t]+)*sshd?(\.service)?($|[\s;&|)])|(^|[\s;&|(/])sshd?[ \t]+(restart|reload)|start[ \t]+([^\s;&|]+[ \t]+)*ssh\.socket($|[\s;&|)])`)

// loadsSSHD reports whether the step p loads sshd. socketOff is whether an
// earlier step of the host stopped or disabled ssh.socket.
func loadsSSHD(p Planned, socketOff bool) bool {
	switch a := p.Step.Args.(type) {
	case *module.Reboot:
		return true
	case *module.Upgrade:
		return module.UpgradesSSHServer(p.Result.Changes)
	case *module.Service:
		switch a.Unit() {
		case "ssh.service", "sshd.service":
			return a.Restarted || a.Reloaded || p.Result.Starts && socketOff && p.Step.ConfirmAccess
		case "ssh.socket":
			return a.Restarted || a.Reloaded || p.Result.Starts
		}
	}
	return false
}

// stopsSocket reports whether the step p stops or disables ssh.socket.
func stopsSocket(p Planned) bool {
	sv, ok := p.Step.Args.(*module.Service)
	return ok && sv.Unit() == "ssh.socket" && (slices.Contains(p.Result.Changes, "stop") || slices.Contains(p.Result.Changes, "disable"))
}
