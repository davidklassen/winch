package run

import (
	"slices"

	"github.com/davidklassen/winch/internal/module"
)

func (p *Plan) suppressMissingUnitFiles() {
	absent := map[string]map[string]bool{}
	add := func(host string, m module.Module) {
		var path string
		switch m := m.(type) {
		case *module.File:
			if m.Absent {
				path = m.Path
			}
		case *module.Link:
			if m.Absent {
				path = m.Path
			}
		}
		if path != "" {
			if absent[host] == nil {
				absent[host] = map[string]bool{}
			}
			absent[host][path] = true
		}
	}
	for _, stage := range p.Stages {
		for _, host := range stage.Hosts {
			for _, step := range host.Steps {
				if step.Handler == nil {
					add(host.Host.Name, step.Step.Args)
				} else if step.Handler.Runs {
					for _, hs := range step.Handler.Steps {
						add(host.Host.Name, hs.Step.Args)
					}
				}
			}
		}
	}
	for _, stage := range p.Stages {
		for _, host := range stage.Hosts {
			for i := range host.Steps {
				res := &host.Steps[i].Result
				if slices.ContainsFunc(res.MissingUnitFiles, func(path string) bool { return absent[host.Host.Name][path] }) {
					res.MissingUnitFiles = nil
				}
			}
		}
	}
}
