package module

import (
	"bufio"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/davidklassen/winch/internal/yamlx"
)

type User struct {
	Name           string         `yaml:"name,required" json:"name"`
	UID            yamlx.ID       `yaml:"uid" json:"uid,omitempty"`
	Group          yamlx.NameOrID `yaml:"group" json:"group,omitempty"`
	System         bool           `yaml:"system" json:"system,omitempty"`
	Home           string         `yaml:"home" json:"home,omitempty"`
	Shell          string         `yaml:"shell" json:"shell,omitempty"`
	AuthorizedKeys *[]string      `yaml:"authorized_keys" json:"authorized_keys,omitempty"`
	Absent         bool           `yaml:"absent" json:"absent,omitempty"`

	// Check sets these for Apply: the useradd, usermod, or userdel command,
	// the home to create for a user that exists, and whether to write the
	// keys.
	account []string
	mkHome  string
	keys    bool
}

// noHome is the home of a system user without home. winch never creates it.
const noHome = "/nonexistent"

func (u *User) Main() string { return u.Name }

func (u *User) Validate() error {
	if err := checkAccountName("name", "user", u.Name); err != nil {
		return err
	}
	if u.Absent {
		return absentTakesNone(arg{"uid", u.UID != ""}, arg{"group", u.Group != ""}, arg{"system", u.System}, arg{"home", u.Home != ""}, arg{"shell", u.Shell != ""}, arg{"authorized_keys", u.AuthorizedKeys != nil})
	}
	if err := checkID("uid", u.UID); err != nil {
		return err
	}
	switch {
	case numberRe.MatchString(string(u.Group)):
		if err := checkID("group", yamlx.ID(u.Group)); err != nil {
			return err
		}
	case u.Group != "":
		if err := checkAccountName("group", "group", string(u.Group)); err != nil {
			return err
		}
	}
	if u.Home != "" {
		if err := checkAbs("home", u.Home); err != nil {
			return err
		}
	}
	if u.Shell != "" {
		if err := checkAbs("shell", u.Shell); err != nil {
			return err
		}
	}
	if u.AuthorizedKeys == nil {
		return nil
	}
	if u.System && u.Home == "" {
		return &yamlx.FieldError{Field: "authorized_keys", Msg: "a system user without home has no home for its keys; set home"}
	}
	seen := map[string]int{}
	for i, k := range *u.AuthorizedKeys {
		key, err := parseKey(k)
		switch {
		case k == "":
			return &yamlx.FieldError{Field: "authorized_keys", Msg: fmt.Sprintf("element %d is empty", i+1)}
		case strings.ContainsAny(k, "\r\n"):
			return &yamlx.FieldError{Field: "authorized_keys", Msg: fmt.Sprintf("element %d has more than one line", i+1)}
		case err != nil:
			return &yamlx.FieldError{Field: "authorized_keys", Msg: fmt.Sprintf("element %d is not a key: %s", i+1, err)}
		case key.typ == "ssh-dss":
			return &yamlx.FieldError{Field: "authorized_keys", Msg: fmt.Sprintf("element %d is an ssh-dss key; Debian 13's sshd rejects ssh-dss keys", i+1)}
		case key.typ == "ssh-rsa" && key.rsaBits < 1024:
			return &yamlx.FieldError{Field: "authorized_keys", Msg: fmt.Sprintf("element %d is a %d-bit RSA key; Debian 13's sshd rejects RSA keys under 1024 bits", i+1, key.rsaBits)}
		}
		if j, ok := seen[string(key.blob)]; ok {
			return &yamlx.FieldError{Field: "authorized_keys", Msg: fmt.Sprintf("element %d has the key of element %d", i+1, j+1)}
		}
		seen[string(key.blob)] = i
	}
	return nil
}

func (u *User) Check(ctx context.Context, st *State, _ func(string)) (Result, error) {
	a, err := readAccounts()
	if err != nil {
		return Result{}, err
	}
	cur, exists := a.user(u.Name)
	if u.Absent {
		return u.checkAbsent(a, cur, exists, st.LoginUID)
	}
	if u.UID != "" && (!exists || cur.uid != u.uid()) {
		if other, ok := a.userByID(u.uid()); ok && other.name != u.Name {
			return Result{}, fmt.Errorf("uid %s belongs to user %s", u.UID, other.name)
		}
	}
	var res Result
	var home, group string
	if exists {
		if err := u.checkLogin(cur, st.LoginUID); err != nil {
			return Result{}, err
		}
		res, home, group, err = u.checkExisting(a, cur)
	} else {
		res, home, group, err = u.checkNew(a)
	}
	if err != nil || u.AuthorizedKeys == nil {
		return res, err
	}
	switch home {
	case noHome:
		return Result{}, fmt.Errorf("user %s has no home (%s); authorized_keys needs one; set home", u.Name, noHome)
	case "/":
		return Result{}, fmt.Errorf("the home of %s is /; authorized_keys needs another home; set home", u.Name)
	}
	if err := u.sshdUsesKeys(ctx, cur, exists, home); err != nil {
		return Result{}, err
	}
	lines, err := u.keyLines(home, group)
	if err != nil {
		return Result{}, err
	}
	if len(lines) > 0 {
		u.keys = true
		if exists && cur.uid == st.LoginUID {
			lines = append([]string{"changes the keys of the login user " + u.Name}, lines...)
		}
		res.Changes = append(res.Changes, lines...)
		if res.Status == OK {
			res = Result{Status: Change, Action: Modify, Changes: lines}
		}
	}
	return res, nil
}

// checkLogin fails when the step changes a field of the login user that the
// next session needs.
func (u *User) checkLogin(cur passwdEntry, login uint32) error {
	if cur.uid != login {
		return nil
	}
	var field string
	switch {
	case u.UID != "" && u.uid() != cur.uid:
		field = "uid"
	case u.Shell != "" && u.Shell != cur.shell:
		field = "shell"
	case u.Home != "" && u.Home != cur.home:
		field = "home"
	default:
		return nil
	}
	return fmt.Errorf("%s is the login user of this session; log in as another user to change its %s", u.Name, field)
}

func (u *User) uid() uint32 {
	id, _ := strconv.ParseUint(string(u.UID), 10, 32)
	return uint32(id)
}

func (u *User) checkAbsent(a accounts, cur passwdEntry, exists bool, login uint32) (Result, error) {
	if !exists {
		return Result{Status: OK}, nil
	}
	if cur.uid == login {
		return Result{}, fmt.Errorf("%s is the login user of this session; log in as another user to remove it", u.Name)
	}
	u.account = []string{"userdel", u.Name}
	res := Result{Status: Change, Action: Remove}
	if removesGroup(a, cur) {
		res.Changes = []string{"remove group " + cur.name}
	}
	return res, nil
}

// removesGroup reports whether userdel removes the primary group of user, as
// shadow's userdel decides.
func removesGroup(a accounts, user passwdEntry) bool {
	g, ok := a.group(strconv.FormatUint(uint64(user.gid), 10))
	// userdel removes the user from the members first.
	others := slices.DeleteFunc(slices.Clone(g.members), func(m string) bool { return m == user.name })
	if !ok || g.name != user.name || len(others) > 0 || !userGroups() {
		return false
	}
	for _, o := range a.users {
		if o.gid == user.gid && o.name != user.name {
			return false
		}
	}
	return true
}

// userGroups reports whether USERGROUPS_ENAB in /etc/login.defs is yes.
func userGroups() bool {
	f, err := os.Open("/etc/login.defs")
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if fields := strings.Fields(sc.Text()); len(fields) == 2 && fields[0] == "USERGROUPS_ENAB" {
			return fields[1] == "yes"
		}
	}
	return false
}

// checkNew plans useradd. It returns the home and the name of the primary
// group of the new user.
func (u *User) checkNew(a accounts) (Result, string, string, error) {
	args := []string{"useradd"}
	var changes []string
	if u.UID != "" {
		changes = append(changes, "uid "+string(u.UID))
		args = append(args, "-u", string(u.UID))
	}
	group := cmp.Or(string(u.Group), u.Name)
	switch g, ok := a.group(group); {
	case ok:
		changes = append(changes, "group "+g.name)
		args = append(args, "-g", group)
		group = g.name
	case u.Group != "":
		changes = append(changes, "group "+group+" (does not exist yet)")
		args = append(args, "-g", group)
	default:
		changes = append(changes, "group "+group+" (new)")
		args = append(args, "-U")
	}
	if u.System {
		changes = append(changes, "system user")
		args = append(args, "-r")
	}
	home, shell := u.Home, u.Shell
	noneMade := u.System && u.Home == ""
	switch {
	case noneMade:
		home = noHome
	case home == "":
		home = "/home/" + u.Name
	}
	if shell == "" {
		shell = "/bin/sh"
		if u.System {
			shell = "/usr/sbin/nologin"
		}
	}
	args = append(args, "-d", home)
	if noneMade {
		changes = append(changes, "home "+noHome+" (not created)")
		args = append(args, "-M")
	} else {
		missing, fi, err := homeState(home)
		if err != nil {
			return Result{}, "", "", err
		}
		if fi != nil {
			st := fi.Sys().(*syscall.Stat_t)
			changes = append(changes, fmt.Sprintf("home %s exists (%s)", home, attrLine(userName(st.Uid), groupName(st.Gid), uint32(st.Mode)&0o7777)))
			args = append(args, "-M")
		} else {
			changes = append(changes, parentChanges(missing[:len(missing)-1])...)
			changes = append(changes, fmt.Sprintf("home %s (%s, files from /etc/skel)", home, attrLine(u.Name, group, 0o700)))
			args = append(args, "-m", "-K", "HOME_MODE=0700")
		}
	}
	changes = append(changes, "shell "+shell+shellNote(shell))
	u.account = append(args, "-s", shell, u.Name)
	return Result{Status: Change, Action: Create, Changes: changes}, home, group, nil
}

// checkExisting plans usermod and a missing home. It returns the home and the
// name of the primary group after the step.
func (u *User) checkExisting(a accounts, cur passwdEntry) (Result, string, string, error) {
	args := []string{"usermod"}
	var changes []string
	if u.UID != "" && u.uid() != cur.uid {
		changes = append(changes, fmt.Sprintf("uid %d → %s, also of the files in the home", cur.uid, u.UID))
		args = append(args, "-u", string(u.UID))
	}
	group := a.groupName(cur.gid)
	if u.Group != "" {
		g, ok := a.group(string(u.Group))
		if !ok || g.gid != cur.gid {
			old, note := group, " (does not exist yet)"
			group = string(u.Group)
			if ok {
				group, note = g.name, ""
			}
			changes = append(changes, "group "+old+" → "+group+note+", also of the files in the home")
			args = append(args, "-g", string(u.Group))
		}
	}
	home := cur.home
	if u.Home != "" && u.Home != cur.home {
		changes = append(changes, "home "+cur.home+" → "+u.Home)
		args = append(args, "-d", u.Home)
		home = u.Home
	}
	if home != noHome {
		missing, fi, err := homeState(home)
		if err != nil {
			return Result{}, "", "", err
		}
		if fi == nil {
			changes = append(changes, parentChanges(missing[:len(missing)-1])...)
			changes = append(changes, fmt.Sprintf("create home %s (%s)", home, attrLine(u.Name, group, 0o700)))
			u.mkHome = home
		}
	}
	if u.Shell != "" && u.Shell != cur.shell {
		changes = append(changes, "shell "+cur.shell+" → "+u.Shell+shellNote(u.Shell))
		args = append(args, "-s", u.Shell)
	}
	if len(args) > 1 {
		u.account = append(args, u.Name)
	}
	if len(changes) == 0 {
		return Result{Status: OK}, home, group, nil
	}
	return Result{Status: Change, Action: Modify, Changes: changes}, home, group, nil
}

func shellNote(shell string) string {
	if _, err := os.Stat(shell); err != nil {
		return " (does not exist yet)"
	}
	return ""
}

// homeState returns the missing parts of home, from the top, or its file info
// when it exists.
func homeState(home string) ([]string, fs.FileInfo, error) {
	dir, missing, err := openPath(home, home)
	if err != nil {
		return nil, nil, err
	}
	defer dir.Close()
	if len(missing) > 0 {
		return missing, nil, nil
	}
	fi, err := dir.Stat(".")
	return nil, fi, err
}

// sshdUsesKeys fails when sshd, as configured before the run, would not use
// the keys of the user in home after the step.
func (u *User) sshdUsesKeys(ctx context.Context, cur passwdEntry, exists bool, home string) error {
	if _, err := os.Stat("/usr/sbin/sshd"); err != nil {
		return nil
	}
	out, err := run(ctx, nil, "sshd", "-T", "-C", "user="+u.Name)
	if err != nil {
		return err
	}
	conf := map[string]string{}
	for line := range strings.Lines(out) {
		key, value, _ := strings.Cut(strings.TrimSpace(line), " ")
		conf[key] = value
	}
	files := strings.Fields(conf["authorizedkeysfile"])
	if !slices.ContainsFunc(files, func(f string) bool {
		return f == ".ssh/authorized_keys" || f == "%h/.ssh/authorized_keys" || f == "~/.ssh/authorized_keys"
	}) {
		return fmt.Errorf("sshd reads the keys of %s from %s (AuthorizedKeysFile), not from ~/.ssh/authorized_keys", u.Name, conf["authorizedkeysfile"])
	}
	if conf["strictmodes"] == "yes" {
		if err := u.safeHome(cur, exists, home); err != nil {
			return err
		}
	}
	if conf["usepam"] == "no" {
		// useradd locks the password of a new user.
		locked := true
		if exists {
			if locked, err = passwordLocked(u.Name); err != nil {
				return err
			}
		}
		if locked {
			return fmt.Errorf(`with UsePAM no, sshd refuses the login of %s: its password is locked with "!"`, u.Name)
		}
	}
	return nil
}

// safeHome fails when sshd with StrictModes ignores the keys in home after the
// step.
func (u *User) safeHome(cur passwdEntry, exists bool, home string) error {
	fi, err := os.Stat(home)
	if errors.Is(err, fs.ErrNotExist) {
		// The step creates the home with mode 0700.
		return nil
	}
	if err != nil {
		return err
	}
	st := fi.Sys().(*syscall.Stat_t)
	owners := []uint32{0}
	if exists {
		// usermod -u also changes the owner of the home.
		owners = append(owners, cur.uid)
	}
	if u.UID != "" {
		owners = append(owners, u.uid())
	}
	if !slices.Contains(owners, st.Uid) {
		return fmt.Errorf("with StrictModes yes, sshd ignores the keys of %s: %s owns %s, not root or %s", u.Name, userName(st.Uid), home, u.Name)
	}
	if st.Mode&0o022 != 0 {
		return fmt.Errorf("with StrictModes yes, sshd ignores the keys of %s: the group or others can write %s (mode %04o)", u.Name, home, st.Mode&0o7777)
	}
	return nil
}

func passwordLocked(name string) (bool, error) {
	data, err := os.ReadFile("/etc/shadow")
	if err != nil {
		return false, err
	}
	locked := false
	err = rows("/etc/shadow", data, 9, func(f []string) error {
		if f[0] == name {
			locked = strings.HasPrefix(f[1], "!")
		}
		return nil
	})
	return locked, err
}

func (u *User) keyText() []byte {
	if len(*u.AuthorizedKeys) == 0 {
		return []byte{}
	}
	return []byte(strings.Join(*u.AuthorizedKeys, "\n") + "\n")
}

// keyLines describes the changes of ~/.ssh and its authorized_keys for the
// home and the primary group after the step.
func (u *User) keyLines(home, group string) ([]string, error) {
	sshDir := path.Join(home, ".ssh")
	file := path.Join(sshDir, "authorized_keys")
	create := []string{
		fmt.Sprintf("create directory %s (%s)", sshDir, attrLine(u.Name, group, 0o700)),
		fmt.Sprintf("create file %s (%s)", file, attrLine(u.Name, group, 0o600)),
	}
	dir, missing, err := openParent(file)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	if len(missing) > 0 {
		return append(create, keyChanges(nil, *u.AuthorizedKeys)...), nil
	}
	fi, err := dir.Stat(".")
	if err != nil {
		return nil, err
	}
	lines, err := prefixed(sshDir, fi, u.Name, group, 0o700)
	if err != nil {
		return nil, err
	}
	fi, exists, err := lstat(dir, "authorized_keys", nil)
	switch {
	case err != nil:
		return nil, err
	case !exists:
		return append(append(lines, create[1]), keyChanges(nil, *u.AuthorizedKeys)...), nil
	case fi.Mode()&fs.ModeSymlink != 0:
		target, _ := dir.Readlink("authorized_keys")
		lines = append(lines, fmt.Sprintf("replace the symbolic link %s to %s", file, target), create[1])
		return append(lines, keyChanges(nil, *u.AuthorizedKeys)...), nil
	case !fi.Mode().IsRegular():
		return nil, fmt.Errorf("%s is %s, not a file", file, kind(fi))
	}
	attr, err := prefixed(file, fi, u.Name, group, 0o600)
	if err != nil {
		return nil, err
	}
	lines = append(lines, attr...)
	f, err := openSame(dir, "authorized_keys", fi)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi.Size() > maxDiff {
		return append(lines, "rewrite "+file+" ("+tooLarge+")"), nil
	}
	data, err := io.ReadAll(io.LimitReader(f, maxDiff+1))
	if err != nil {
		return nil, err
	}
	want := u.keyText()
	if string(data) == string(want) {
		return lines, nil
	}
	var cur []string
	if len(data) > 0 {
		cur = strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	}
	changes := keyChanges(cur, *u.AuthorizedKeys)
	if len(changes) == 0 {
		changes = []string{"rewrite " + file}
	}
	return append(lines, changes...), nil
}

// prefixed returns the owner, group, and mode changes of the path p with the
// path in front.
func prefixed(p string, fi fs.FileInfo, owner, group string, mode uint32) ([]string, error) {
	changes, err := attrChanges(fi, owner, group, mode)
	for i, c := range changes {
		changes[i] = p + ": " + c
	}
	return changes, err
}

func (u *User) Apply(ctx context.Context, _ func(string)) error {
	if u.account != nil {
		if _, err := run(ctx, nil, u.account[0], u.account[1:]...); err != nil {
			return err
		}
	}
	if u.mkHome == "" && !u.keys {
		return nil
	}
	a, err := readAccounts()
	if err != nil {
		return err
	}
	e, ok := a.user(u.Name)
	if !ok {
		return fmt.Errorf("user %s does not exist", u.Name)
	}
	if u.mkHome != "" {
		if err := makeHome(u.mkHome, e.uid, e.gid); err != nil {
			return err
		}
	}
	if u.keys {
		return u.writeKeys(e)
	}
	return nil
}

func makeHome(home string, uid, gid uint32) error {
	dir, missing, err := openPath(home, home)
	if err != nil {
		return err
	}
	defer dir.Close()
	if len(missing) == 0 {
		return nil
	}
	parent, err := mkdirs(dir, missing[:len(missing)-1])
	if err != nil {
		return err
	}
	defer parent.Close()
	sub, err := mkdir(parent, path.Base(home), uid, gid, 0o700)
	if err != nil {
		return err
	}
	return sub.Close()
}

// writeKeys writes ~/.ssh/authorized_keys of the user e, and sets the owner,
// group, and mode of both.
func (u *User) writeKeys(e passwdEntry) error {
	dir, missing, err := openParent(path.Join(e.home, ".ssh", "authorized_keys"))
	if err != nil {
		return err
	}
	defer dir.Close()
	switch {
	case len(missing) > 1:
		return fmt.Errorf("%s does not exist", missing[0])
	case len(missing) == 1:
		sub, err := mkdir(dir, ".ssh", e.uid, e.gid, 0o700)
		if err != nil {
			return err
		}
		defer sub.Close()
		dir = sub
	default:
		if err := setRootAttrs(dir, e.uid, e.gid, 0o700); err != nil {
			return err
		}
	}
	return writeFile(dir, "authorized_keys", u.keyText(), e.uid, e.gid, 0o600, func(tmp string) error {
		return dir.Rename(tmp, "authorized_keys")
	})
}
