package module

import "path"

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
