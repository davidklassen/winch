package module

import (
	"cmp"
	"path"
)

// Writer is a module that writes known paths on the host. A dir step with
// purge keeps them.
type Writer interface {
	Writes() []string
}

func (f *File) Writes() []string { return present(f.Absent, f.Path) }

func (d *Dir) Writes() []string { return present(d.Absent, d.Path) }

func (l *Link) Writes() []string { return present(l.Absent, l.Path) }

func (l *Line) Writes() []string { return present(l.Absent, l.Path) }

func (u *Unit) Writes() []string { return []string{u.Path()} }

func (r *Repo) Writes() []string {
	out := []string{r.SourcePath()}
	if r.Key != "" || r.KeyData != nil {
		out = append(out, r.keyPath())
	}
	return out
}

func (d *Download) Writes() []string { return []string{d.Main()} }

// Writes returns the home that the step gives, or the home that useradd
// gives a new user that is not a system user.
func (u *User) Writes() []string {
	home := u.Home
	switch {
	case u.Absent:
		return nil
	case home == "" && u.System:
		return nil
	case home == "":
		home = "/home/" + u.Name
	}
	if u.AuthorizedKeys == nil {
		return []string{home}
	}
	ssh := path.Join(home, ".ssh")
	return []string{home, ssh, path.Join(ssh, "authorized_keys")}
}

func (c *Cmd) Writes() []string {
	if c.Creates == "" {
		return nil
	}
	return []string{c.Creates}
}

// Owned is a path with the owner and group that a step wants. An empty owner
// or group is one that the step does not set. Tree says that the step also
// sets them on everything below the path.
type Owned struct {
	Path, Owner, Group string
	Tree               bool
}

// Owns returns the paths whose owner and group the step m compares with the
// host on every run. The plan does not know the host here: a stock file counts
// as root, and the keys of a user as the group with the name of the user. A
// step that writes the owner or group decides. An unpack is not here: it
// compares its record, not the tree.
func Owns(m Module) []Owned {
	switch m := m.(type) {
	case *File:
		if !m.hasContent() {
			return []Owned{{Path: m.Path, Owner: string(m.Owner), Group: string(m.Group)}}
		}
		return []Owned{{Path: m.Path, Owner: cmp.Or(string(m.Owner), "root"), Group: cmp.Or(string(m.Group), "root")}}
	case *Dir:
		if m.Absent {
			return nil
		}
		return []Owned{{m.Path, cmp.Or(string(m.Owner), "root"), cmp.Or(string(m.Group), "root"), m.Recurse}}
	case *Download:
		if m.Unpack != "" {
			return nil
		}
		return []Owned{{Path: m.Path, Owner: cmp.Or(string(m.Owner), "root"), Group: cmp.Or(string(m.Group), "root")}}
	case *Unit:
		return Owns(m.File())
	case *Repo, *Firewall:
		var out []Owned
		for _, p := range m.(Writer).Writes() {
			out = append(out, Owned{Path: p, Owner: "root", Group: "root"})
		}
		return out
	case *User:
		if m.AuthorizedKeys == nil {
			return nil
		}
		group := cmp.Or(string(m.Group), m.Name)
		w := m.Writes()
		return []Owned{{Path: w[1], Owner: m.Name, Group: group}, {Path: w[2], Owner: m.Name, Group: group}}
	}
	return nil
}

func present(absent bool, p string) []string {
	if absent {
		return nil
	}
	return []string{p}
}

func (h *Hostname) Writes() []string { return []string{hostnameFile} }

func (z *Timezone) Writes() []string { return []string{localtime, TimezoneFile} }

func (c *Certbot) Writes() []string {
	return []string{renewalPath(letsencrypt, c.Name), path.Join(letsencrypt, "live", c.Name), path.Join(letsencrypt, "archive", c.Name)}
}
