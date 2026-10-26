package module

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// passwdEntry is a row of /etc/passwd.
type passwdEntry struct {
	name     string
	uid, gid uint32
	home     string
	shell    string
}

// groupEntry is a row of /etc/group.
type groupEntry struct {
	name    string
	gid     uint32
	members []string
}

// rows returns the fields of each line of data that is not empty or a
// comment, as glibc reads them. Each line must have n fields.
func rows(file string, data []byte, n int, row func(f []string) error) error {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for i := 1; sc.Scan(); i++ {
		if sc.Text() == "" || strings.HasPrefix(sc.Text(), "#") {
			continue
		}
		f := strings.Split(sc.Text(), ":")
		if len(f) != n {
			return fmt.Errorf("%s:%d: expected %d fields, got %d", file, i, n, len(f))
		}
		if err := row(f); err != nil {
			return fmt.Errorf("%s:%d: %w", file, i, err)
		}
	}
	return sc.Err()
}

func parseID(what, s string) (uint32, error) {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("the %s %q is not a number", what, s)
	}
	return uint32(n), nil
}

func parsePasswd(file string, data []byte) ([]passwdEntry, error) {
	var out []passwdEntry
	err := rows(file, data, 7, func(f []string) error {
		uid, err := parseID("UID", f[2])
		if err != nil {
			return err
		}
		gid, err := parseID("GID", f[3])
		if err != nil {
			return err
		}
		// login uses / for an empty home and /bin/sh for an empty shell.
		e := passwdEntry{name: f[0], uid: uid, gid: gid, home: f[5], shell: f[6]}
		if e.home == "" {
			e.home = "/"
		}
		if e.shell == "" {
			e.shell = "/bin/sh"
		}
		out = append(out, e)
		return nil
	})
	return out, err
}

func parseGroup(file string, data []byte) ([]groupEntry, error) {
	var out []groupEntry
	err := rows(file, data, 4, func(f []string) error {
		gid, err := parseID("GID", f[2])
		if err != nil {
			return err
		}
		e := groupEntry{name: f[0], gid: gid}
		if f[3] != "" {
			e.members = strings.Split(f[3], ",")
		}
		out = append(out, e)
		return nil
	})
	return out, err
}

// accounts are the users and groups of the host.
type accounts struct {
	users  []passwdEntry
	groups []groupEntry
}

func readAccounts() (accounts, error) {
	var a accounts
	data, err := os.ReadFile("/etc/passwd")
	if err == nil {
		a.users, err = parsePasswd("/etc/passwd", data)
	}
	if err != nil {
		return a, err
	}
	data, err = os.ReadFile("/etc/group")
	if err == nil {
		a.groups, err = parseGroup("/etc/group", data)
	}
	return a, err
}

func (a accounts) user(name string) (passwdEntry, bool) {
	for _, u := range a.users {
		if u.name == name {
			return u, true
		}
	}
	return passwdEntry{}, false
}

func (a accounts) userByID(uid uint32) (passwdEntry, bool) {
	for _, u := range a.users {
		if u.uid == uid {
			return u, true
		}
	}
	return passwdEntry{}, false
}

// group finds a group by name, or by ID for a value of only digits.
func (a accounts) group(nameOrID string) (groupEntry, bool) {
	id, err := strconv.ParseUint(nameOrID, 10, 32)
	for _, g := range a.groups {
		if g.name == nameOrID || err == nil && g.gid == uint32(id) {
			return g, true
		}
	}
	return groupEntry{}, false
}

// groupName returns the name of the group gid, or the number.
func (a accounts) groupName(gid uint32) string {
	g, ok := a.group(strconv.FormatUint(uint64(gid), 10))
	if !ok {
		return strconv.FormatUint(uint64(gid), 10)
	}
	return g.name
}
