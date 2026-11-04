package run

import (
	"regexp"
	"slices"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
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
		unguarded = "sshd loads a changed config without an access check; reload it in a service handler with confirm_access: true"
		untested  = "sshd's config changes, and no step reloads sshd with confirm_access: true; the new config loads untested at the next restart"
	)
	type change struct {
		host   string
		pos    yamlx.Pos
		stores []store
	}
	var pending []change
	load := func(host string, s Planned, owner store, thenRuns bool) {
		switch {
		case s.LoadsSSHD && s.Step.ConfirmAccess:
			pending = slices.DeleteFunc(pending, func(c change) bool { return c.host == host && slices.Contains(c.stores, owner) })
		case s.LoadsSSHD, thenRuns && sshdThen.MatchString(s.Step.Then):
			before := len(pending)
			pending = slices.DeleteFunc(pending, func(c change) bool { return c.host == host })
			if len(pending) != before {
				warn(s.Step.Pos, unguarded)
			}
		}
	}
	for _, sp := range p.Stages {
		for _, hp := range sp.Hosts {
			name := hp.Host.Name
			if p.Failed[name] != nil {
				continue
			}
			for _, s := range hp.Steps {
				if s.Handler == nil {
					if s.Result.Status == module.Change && slices.ContainsFunc(module.Touches(s.Step.Args), func(t module.Touch) bool { return module.SSHDConfig(t.Path) }) && !slices.Contains(s.Result.Changes, module.SSHSocketRestart) {
						pending = append(pending, change{name, s.Step.Pos, stores(sp.Stage, s)})
					}
					load(name, s, ownStore(sp.Stage, s), s.ThenRuns)
					continue
				}
				if !s.Handler.Runs {
					continue
				}
				for _, hs := range s.Handler.Steps {
					load(name, hs, storeOf(s.Handler.Handler), true)
				}
			}
		}
	}
	for _, c := range pending {
		warn(c.pos, untested)
	}
	return out
}

// store names the rollback store of a recipe, or of a stage.
type store struct{ recipe, pipeline, stage string }

func storeOf(h *project.Handler) store {
	if h.Recipe != nil {
		return store{recipe: h.Recipe.Name}
	}
	return store{pipeline: h.Pipeline, stage: h.Stage}
}

// stores returns the rollback stores that keep the old state of the step p,
// as guard sends them to the helper.
func stores(stage *project.Stage, p Planned) []store {
	g := guard(stage, p)
	var out []store
	if g.Save {
		out = append(out, ownStore(stage, p))
	}
	for _, h := range p.Step.Notify {
		if slices.Contains(g.Handlers, h.Record()) {
			out = append(out, storeOf(h))
		}
	}
	return append(out, p.SSHD...)
}

// sshdStores sets LoadsSSHD on each step that loads sshd, and SSHD on each step
// that changes sshd's config. A guarded load of sshd loads the files of every
// earlier step, not only those of its own store. A handler that the plan does
// not expect to run tests nothing: the helper would put back its store at the
// end of the session.
func (p *Plan) sshdStores() {
	type ref struct {
		p     *Planned
		store store
	}
	steps := map[string][]ref{}
	socketOff := map[string]bool{}
	for _, sp := range p.Stages {
		for _, hp := range sp.Hosts {
			name := hp.Host.Name
			for i := range hp.Steps {
				s := &hp.Steps[i]
				if s.Handler == nil {
					s.LoadsSSHD = loadsSSHD(*s, socketOff[name])
					socketOff[name] = socketOff[name] || stopsSocket(*s)
					steps[name] = append(steps[name], ref{s, ownStore(sp.Stage, *s)})
					continue
				}
				for j := range s.Handler.Steps {
					hs := &s.Handler.Steps[j]
					hs.LoadsSSHD = loadsSSHD(*hs, socketOff[name])
					if s.Handler.Runs {
						steps[name] = append(steps[name], ref{hs, storeOf(s.Handler.Handler)})
					}
				}
			}
		}
	}
	for _, refs := range steps {
		var later []store
		for _, r := range slices.Backward(refs) {
			if slices.ContainsFunc(module.Touches(r.p.Step.Args), func(t module.Touch) bool { return module.SSHDConfig(t.Path) }) {
				r.p.SSHD = slices.Clone(later)
			}
			if r.p.LoadsSSHD && r.p.Step.ConfirmAccess && !slices.Contains(later, r.store) {
				later = append(later, r.store)
			}
		}
	}
}

// ownStore is the store of the step p of stage: that of its recipe, or of
// the stage.
func ownStore(stage *project.Stage, p Planned) store {
	if p.In != nil {
		return store{recipe: p.In.Recipe.Name}
	}
	return store{pipeline: stage.Pipeline, stage: stage.Name}
}

// name is the store as the helper takes it: a recipe, or <pipeline>\t<stage>.
func (s store) name() string {
	if s.recipe != "" {
		return s.recipe
	}
	return s.pipeline + "\t" + s.stage
}

// sshdThen matches a command that restarts or reloads ssh or sshd, or that
// starts or restarts ssh.socket: systemctl restart ssh, service ssh reload,
// systemctl start ssh.socket.
var sshdThen = regexp.MustCompile(`(restart|reload)[ \t]+([^\s;&|]+[ \t]+)*sshd?(\.service)?($|[\s;&|)])|(^|[\s;&|(/])sshd?[ \t]+(restart|reload)|start[ \t]+([^\s;&|]+[ \t]+)*ssh\.socket($|[\s;&|)])`)

// loadsSSHD reports whether the step p loads sshd. socketOff is whether an
// earlier step of the host stopped or disabled ssh.socket. The plan does not
// check a handler step, so a start in a handler does not count.
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
