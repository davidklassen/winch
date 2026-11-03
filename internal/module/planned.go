package module

import (
	"path"
	"slices"
	"strings"
)

// Planned is what an earlier file, dir, or link step of the run leaves at a
// path. Kind is "file", "dir", "link", or "" for nothing. A file that holds
// content that the plan does not know yet has no SHA256.
type Planned struct {
	Path   string `json:"path"`
	Kind   string `json:"kind,omitempty"`
	Target string `json:"target,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Mode   uint32 `json:"mode,omitempty"`
}

// PlannedPkg is a version of a package that an earlier pkg or upgrade step
// installs, with the apt flags of the package index that has it. Named is
// set for a package that a pkg step names.
type PlannedPkg struct {
	Version string   `json:"version"`
	Arch    string   `json:"arch"`
	Index   []string `json:"index,omitempty"`
	Named   bool     `json:"named,omitempty"`
}

// plan records what a step leaves at a path, in place of the earlier records
// of the path, and of the paths below it when it is no directory.
func (st *State) plan(p Planned) {
	if st != nil {
		st.Paths = append(slices.DeleteFunc(st.Paths, func(e Planned) bool {
			return e.Path == p.Path || p.Kind != "dir" && below(e.Path, p.Path)
		}), p)
	}
}

// planned returns what the earlier steps leave at p. ok is false when no
// step changes p: the host has what is there now.
func (st *State) planned(p string) (Planned, bool) {
	if st == nil {
		return Planned{}, false
	}
	for i := len(st.Paths) - 1; i >= 0; i-- {
		e := st.Paths[i]
		switch {
		case e.Path == p:
			return e, true
		case below(p, e.Path) && e.Kind != "dir":
			return Planned{Path: p}, true
		}
	}
	return Planned{}, false
}

// resolve replaces each parent of p that an earlier link step links with the
// target of that link.
func (st *State) resolve(p string) string {
	if st == nil {
		return p
	}
	for links := 0; links <= 40; links++ {
		next, ok := st.throughLink(p)
		if !ok {
			return p
		}
		p = next
	}
	return p
}

// throughLink replaces the first parent of p that an earlier link step links.
func (st *State) throughLink(p string) (string, bool) {
	for i := 1; i < len(p); i++ {
		if p[i] != '/' {
			continue
		}
		d := p[:i]
		e, ok := st.planned(d)
		if !ok || e.Kind != "link" {
			continue
		}
		target := e.Target
		if !path.IsAbs(target) {
			target = path.Join(path.Dir(d), target)
		}
		return path.Join(target, strings.TrimPrefix(p, d)), true
	}
	return p, false
}

// below reports whether p is inside the directory d.
func below(p, d string) bool {
	return strings.HasPrefix(p, strings.TrimSuffix(d, "/")+"/")
}
