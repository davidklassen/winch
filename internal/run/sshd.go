package run

import (
	"regexp"
	"slices"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/yamlx"
)

// sshdWarnings warns at each step without confirm_access that restarts or
// reloads sshd after an earlier step of its host changed sshd's config. It
// also warns at each change of sshd's config that no later step loads, or
// that a guarded reload loads but its rollback cannot put back.
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
	loaded := func(host string, guard *store) {
		pending = slices.DeleteFunc(pending, func(c change) bool {
			return c.host == host && (guard == nil || slices.Contains(c.stores, *guard))
		})
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
					if s.Result.Status == module.Change && slices.ContainsFunc(module.Touches(s.Step.Args), func(t module.Touch) bool { return module.SSHDConfig(t.Path) }) {
						changed[name] = true
						if !slices.Contains(s.Result.Changes, module.SSHSocketRestart) {
							pending = append(pending, change{name, s.Step.Pos, stores(sp.Stage, s)})
						}
					}
					if changed[name] && s.ThenRuns && sshdThen.MatchString(s.Step.Then) {
						warn(s.Step.Pos, unguarded)
						loaded(name, nil)
					}
					continue
				}
				if !changed[name] || !s.Handler.Runs {
					continue
				}
				for _, hs := range s.Handler.Steps {
					loads, guarded := loadsSSHD(hs.Step)
					if !loads {
						continue
					}
					if !guarded {
						warn(hs.Step.Pos, unguarded)
						loaded(name, nil)
						continue
					}
					owner := storeOf(s.Handler.Handler)
					loaded(name, &owner)
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
		out = append(out, store{g.Recipe, g.Pipeline, g.Stage})
	}
	for _, h := range p.Step.Notify {
		if slices.Contains(g.Handlers, h.Record()) {
			out = append(out, storeOf(h))
		}
	}
	return out
}

// sshdThen matches a command that restarts or reloads ssh or sshd:
// systemctl restart ssh, service ssh reload.
var sshdThen = regexp.MustCompile(`(restart|reload)[ \t]+([^\s;&|]+[ \t]+)*sshd?(\.service)?($|[\s;&|)])|(^|[\s;&|(/])sshd?[ \t]+(restart|reload)`)

// loadsSSHD reports whether the handler step st restarts or reloads sshd,
// and whether the access check guards it. The check does not cover a then.
func loadsSSHD(st project.Step) (loads, guarded bool) {
	if sv, ok := st.Args.(*module.Service); ok && (sv.Restarted || sv.Reloaded) && (sv.Unit() == "ssh.service" || sv.Unit() == "sshd.service") {
		return true, st.ConfirmAccess
	}
	return sshdThen.MatchString(st.Then), false
}
