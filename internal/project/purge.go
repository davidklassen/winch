package project

import (
	"path"
	"slices"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/yamlx"
)

func purgeWarnings(invs []*Inventory, pipelines, selected []*Pipeline) []*yamlx.Error {
	type source struct {
		pos   yamlx.Pos
		paths []string
	}
	type warning struct {
		pos yamlx.Pos
		dir string
	}
	seen := map[warning]bool{}
	var out []*yamlx.Error
	for _, inv := range invs {
		sources := map[string][]source{}
		purges := map[string][]string{}
		for _, pl := range pipelines {
			for _, stage := range pl.Stages {
				hosts, _ := inv.Match(stage.Hosts)
				for _, st := range stage.Steps {
					steps := []Step{st}
					if st.Recipe != nil {
						steps = slices.Clone(st.Recipe.Steps)
						for _, h := range st.Recipe.Handlers {
							steps = append(steps, h.Steps...)
						}
					}
					for _, step := range steps {
						args := step.Args
						if args == nil && step.args != nil {
							args, _ = module.New(step.Module)
							if err := yamlx.DecodeLazy(step.args.node, args); err != nil {
								continue
							}
						}
						var paths []string
						if slices.Contains(selected, pl) && (step.then != nil || len(step.Notify) > 0) {
							switch args.(type) {
							case *module.File, *module.Dir, *module.Link, *module.Line:
								paths = []string{args.Main()}
							default:
								if writer, ok := args.(module.Writer); ok {
									paths = writer.Writes()
								}
							}
						}
						var dir string
						if d, ok := args.(*module.Dir); ok && d.Purge && !d.Absent && !hasKeep(step, d) {
							dir = d.Path
						}
						for _, host := range hosts {
							if len(paths) > 0 {
								sources[host.Name] = append(sources[host.Name], source{step.Pos, paths})
							}
							if dir != "" {
								purges[host.Name] = append(purges[host.Name], dir)
							}
						}
					}
				}
			}
		}
		for _, host := range inv.Hosts {
			for _, source := range sources[host.Name] {
				for _, dir := range purges[host.Name] {
					for _, p := range source.paths {
						key := warning{source.pos, dir}
						if p != "" && path.Dir(p) == dir && !seen[key] {
							seen[key] = true
							out = append(out, yamlx.Errorf(source.pos, "purge of %s may remove files made by then or a handler; add keep", dir))
						}
					}
				}
			}
		}
	}
	return out
}

func hasKeep(st Step, d *module.Dir) bool {
	if len(d.KeepPatterns) != 0 {
		return true
	}
	if st.args != nil {
		pair := find(st.args.node, []string{"keep"})
		return pair != nil && pair.Value.Tag != ""
	}
	return false
}
