package module

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"unicode"

	"github.com/davidklassen/winch/internal/yamlx"
)

type User struct {
	Name           string         `yaml:"name,required" json:"name"`
	UID            yamlx.ID       `yaml:"uid" json:"uid,omitempty"`
	Group          yamlx.NameOrID `yaml:"group" json:"group,omitempty"`
	System         bool           `yaml:"system" json:"system,omitempty"`
	Home           string         `yaml:"home" json:"home,omitempty"`
	Shell          string         `yaml:"shell" json:"shell,omitempty"`
	Groups         *[]string      `yaml:"groups" json:"groups,omitempty"`
	AddGroups      *[]string      `yaml:"add_groups" json:"add_groups,omitempty"`
	Password       string         `yaml:"password" json:"password,omitempty"`
	Comment        string         `yaml:"comment" json:"comment,omitempty"`
	AuthorizedKeys *[]string      `yaml:"authorized_keys" json:"authorized_keys,omitempty"`
	Absent         bool           `yaml:"absent" json:"absent,omitempty"`

	// Check sets these for Apply: the useradd, usermod, or userdel command,
	// the home to create for a user that exists, and whether to set the
	// password and write the keys.
	account  []string
	mkHome   string
	password bool
	// opens are the account files that the planned commands open for writing.
	opens []string
	keys  bool
	// keyHome is the home of the keys that Apply writes.
	keyHome string
	// missing marks a step that only adds groups to a user that does not
	// exist.
	missing bool
	// loginGroups holds the groups of the login user before a step that
	// adds groups to it.
	loginGroups *[]string
}

// hashRe matches a crypt hash, such as $y$… or $6$…, also locked with "!",
// and the passwords "!" and "*" that lock the account.
var hashRe = regexp.MustCompile(`^(!?\$[0-9a-z]+\$[./0-9A-Za-z$=,+-]+|!|\*)$`)

// checkHash fails for a password that is not a crypt hash. Check, not
// Validate, runs it: a password from a secret is a placeholder in Validate.
func checkHash(pw string) error {
	if !hashRe.MatchString(pw) {
		return errors.New(`password is not a crypt hash, such as one from mkpasswd -m yescrypt, or "!" or "*"`)
	}
	return nil
}

// noHome is the home of a system user without home. winch never creates it.
const noHome = "/nonexistent"

func (u *User) Main() string { return u.Name }

func (u *User) Validate() error {
	if err := checkAccountName("name", "user", u.Name); err != nil {
		return err
	}
	if u.Absent {
		return absentTakesNone(arg{"uid", u.UID != ""}, arg{"group", u.Group != ""}, arg{"system", u.System}, arg{"home", u.Home != ""}, arg{"shell", u.Shell != ""}, arg{"groups", u.Groups != nil}, arg{"add_groups", u.AddGroups != nil}, arg{"password", u.Password != ""}, arg{"comment", u.Comment != ""}, arg{"authorized_keys", u.AuthorizedKeys != nil})
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
	field, groups := "groups", u.Groups
	if u.AddGroups != nil {
		if u.Groups != nil {
			return &yamlx.FieldError{Field: "add_groups", Msg: "a step takes groups or add_groups, not both"}
		}
		field, groups = "add_groups", u.AddGroups
	}
	if groups != nil {
		seen := map[string]int{}
		for i, g := range *groups {
			if err := checkAccountName(field, "group", g); err != nil {
				return err
			}
			if j, ok := seen[g]; ok {
				return &yamlx.FieldError{Field: field, Msg: fmt.Sprintf("element %d repeats element %d", i+1, j+1)}
			}
			seen[g] = i
		}
	}
	switch {
	case strings.ContainsFunc(u.Comment, unicode.IsControl):
		return &yamlx.FieldError{Field: "comment", Msg: "has a control character"}
	case strings.Contains(u.Comment, ":"):
		return &yamlx.FieldError{Field: "comment", Msg: `must not have ":"`}
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
			return &yamlx.FieldError{Field: "authorized_keys", Msg: fmt.Sprintf("element %d is an ssh-dss key; sshd rejects ssh-dss keys", i+1)}
		case key.typ == "ssh-rsa" && key.rsaBits < 1024:
			return &yamlx.FieldError{Field: "authorized_keys", Msg: fmt.Sprintf("element %d is a %d-bit RSA key; sshd rejects RSA keys under 1024 bits", i+1, key.rsaBits)}
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
		return u.checkAbsent(a, cur, exists, st)
	}
	if u.Password != "" {
		if err := checkHash(u.Password); err != nil {
			return Result{}, err
		}
	}
	if u.UID != "" && (!exists || cur.uid != u.uid()) {
		if other, ok := a.userByID(u.uid()); ok && other.name != u.Name {
			return Result{}, fmt.Errorf("uid %s belongs to user %s", u.UID, other.name)
		}
	}
	var res Result
	var home, group string
	if exists {
		if err := u.checkLogin(a, cur, st.LoginUID); err != nil {
			return Result{}, err
		}
		res, home, group, err = u.checkExisting(a, cur)
	} else if u.OnlyAddsGroups() {
		return u.checkMissing(a), nil
	} else {
		if err := checkNewAccount("user", u.Name); err != nil {
			return Result{}, err
		}
		res, home, group, err = u.checkNew(a)
	}
	if err != nil {
		return res, err
	}
	if err := noFlagsAt(u.opens...); err != nil {
		return Result{}, err
	}
	// sshd's AllowGroups, DenyGroups, and Match Group read the groups at the
	// next login.
	if u.loginGroups != nil {
		res.Guard = true
		res.Changes = append([]string{"changes the groups of the login user " + u.Name}, res.Changes...)
	}
	if u.AuthorizedKeys == nil {
		if exists && cur.uid == st.LoginUID && strings.HasPrefix(u.Password, "!") {
			err = u.checkSSHD(ctx, st.SSHConnection, a, cur, exists, home, group)
		}
		return res, err
	}
	switch home {
	case noHome:
		return Result{}, fmt.Errorf("user %s has no home (%s); authorized_keys needs one; set home", u.Name, noHome)
	case "/":
		return Result{}, fmt.Errorf("the home of %s is /; authorized_keys needs another home; set home", u.Name)
	}
	if err := u.checkSSHD(ctx, st.SSHConnection, a, cur, exists, home, group); err != nil {
		return Result{}, err
	}
	lines, err := u.keyLines(home, group)
	if err != nil {
		return Result{}, err
	}
	if len(lines) > 0 {
		u.keys, u.keyHome = true, home
		res.Changes = append(res.Changes, lines...)
		if res.Status == OK {
			res = Result{Status: Change, Action: Modify, Changes: lines}
		}
	}
	return res, nil
}

// OnlyAddsGroups reports whether the step has only name and add_groups. Such a
// step does not create the user.
func (u *User) OnlyAddsGroups() bool {
	return u.AddGroups != nil && u.UID == "" && u.Group == "" && !u.System && u.Home == "" && u.Shell == "" && u.Password == "" && u.Comment == "" && u.AuthorizedKeys == nil
}

// checkMissing plans the groups of a step that only adds groups to a user that
// does not exist yet. An earlier step can create the user.
func (u *User) checkMissing(a accounts) Result {
	u.missing = true
	changes := []string{"user does not exist yet"}
	for _, g := range *u.AddGroups {
		line := "add to group " + g
		if _, ok := a.group(g); !ok {
			line += " (does not exist yet)"
		}
		changes = append(changes, line)
	}
	return Result{Status: Change, Action: Modify, Changes: changes}
}

// checkLogin fails when the step changes a field of the login user that the
// next session needs, or removes a group from the user. It sets loginGroups
// when the step adds groups to the user.
func (u *User) checkLogin(a accounts, cur passwdEntry, login uint32) error {
	if cur.uid != login {
		return nil
	}
	have := a.groupsOf(u.Name)
	primary, ok := a.group(string(u.Group))
	var field string
	switch {
	case u.UID != "" && u.uid() != cur.uid:
		field = "uid"
	case u.Group != "" && (!ok || primary.gid != cur.gid):
		field = "group"
	case u.Shell != "" && u.Shell != cur.shell:
		field = "shell"
	case u.Home != "" && u.Home != cur.home:
		field = "home"
	case u.Groups != nil && slices.ContainsFunc(have, func(g string) bool { return !slices.Contains(*u.Groups, g) }):
		field = "groups"
	default:
		if want := cmp.Or(u.Groups, u.AddGroups); want != nil && slices.ContainsFunc(*want, func(g string) bool { return !slices.Contains(have, g) }) {
			old := append([]string{}, have...)
			u.loginGroups = &old
		}
		return nil
	}
	return fmt.Errorf("%s is the login user of this session; log in as another user to change its %s", u.Name, field)
}

// Undo returns the step that removes the login user from the groups that a
// checked step adds. It returns nil for another step.
func (u *User) Undo() *User {
	if u.loginGroups == nil {
		return nil
	}
	return &User{Name: u.Name, Groups: u.loginGroups}
}

func (u *User) uid() uint32 {
	id, _ := strconv.ParseUint(string(u.UID), 10, 32)
	return uint32(id)
}

func (u *User) checkAbsent(a accounts, cur passwdEntry, exists bool, st *State) (Result, error) {
	if !exists {
		return Result{Status: OK}, nil
	}
	if cur.uid == st.LoginUID {
		return Result{}, fmt.Errorf("%s is the login user of this session; log in as another user to remove it", u.Name)
	}
	if err := noFlagsAt("/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"); err != nil {
		return Result{}, err
	}
	u.account = []string{"userdel", u.Name}
	st.RemovedUsers = append(st.RemovedUsers, u.Name)
	res := Result{Status: Change, Action: Remove}
	if removesGroup(a, cur, st.RemovedUsers) {
		res.Changes = []string{"remove group " + cur.name}
	}
	procs, err := userProcesses("/proc", cur.uid)
	if err != nil {
		return Result{}, err
	}
	if len(procs) > 0 {
		res.Changes = append(res.Changes, fmt.Sprintf("processes of %s run (%s); userdel fails while they run", u.Name, strings.Join(procs, ", ")))
	}
	return res, nil
}

// removesGroup reports whether userdel removes the primary group of user, as
// shadow's userdel decides. The removed users are gone by then.
func removesGroup(a accounts, user passwdEntry, removed []string) bool {
	gone := func(name string) bool { return name == user.name || slices.Contains(removed, name) }
	g, ok := a.group(strconv.FormatUint(uint64(user.gid), 10))
	// userdel removes the user from the members first.
	others := slices.DeleteFunc(slices.Clone(g.members), gone)
	if !ok || g.name != user.name || len(others) > 0 || !userGroups() {
		return false
	}
	for _, o := range a.users {
		if o.gid == user.gid && !gone(o.name) {
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
		switch {
		case fi != nil:
			st := fi.Sys().(*syscall.Stat_t)
			changes = append(changes, fmt.Sprintf("home %s exists (%s)", home, attrLine(userName(st.Uid), groupName(st.Gid), uint32(st.Mode)&0o7777)))
			args = append(args, "-M")
		default:
			skel := ""
			if u.System {
				// useradd -m copies /etc/skel also for a system user.
				args = append(args, "-M")
				u.mkHome = home
			} else {
				skel = ", files from /etc/skel"
				args = append(args, "-m", "-K", "HOME_MODE=0700")
			}
			changes = append(changes, parentChanges(missing[:len(missing)-1])...)
			changes = append(changes, fmt.Sprintf("home %s (%s%s)", home, attrLine(u.Name, group, 0o700), skel))
		}
	}
	note, err := checkShell(shell)
	if err != nil {
		return Result{}, "", "", err
	}
	changes = append(changes, "shell "+shell+note)
	args = append(args, "-s", shell)
	if groups := cmp.Or(u.Groups, u.AddGroups); groups != nil && len(*groups) > 0 {
		names := slices.Clone(*groups)
		for i, g := range names {
			if _, ok := a.group(g); !ok {
				names[i] += " (does not exist yet)"
			}
		}
		changes = append(changes, "groups "+strings.Join(names, ", "))
		args = append(args, "-G", strings.Join(*groups, ","))
	}
	if u.Comment != "" {
		changes = append(changes, fmt.Sprintf("comment %q", u.Comment))
		args = append(args, "-c", u.Comment)
	}
	if u.Password != "" {
		changes = append(changes, "set password")
		u.password = true
	}
	u.opens = []string{"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"}
	u.account = append(args, u.Name)
	return Result{Status: Change, Action: Create, Changes: changes}, home, group, nil
}

// checkExisting plans usermod and a missing home. It returns the home and the
// name of the primary group after the step.
func (u *User) checkExisting(a accounts, cur passwdEntry) (Result, string, string, error) {
	args := []string{"usermod"}
	var changes []string
	if u.UID != "" && u.uid() != cur.uid {
		changes = append(changes, fmt.Sprintf("uid %d → %s, also of the files in the home; other files keep the old uid", cur.uid, u.UID))
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
		note, err := checkShell(u.Shell)
		if err != nil {
			return Result{}, "", "", err
		}
		changes = append(changes, "shell "+cur.shell+" → "+u.Shell+note)
		args = append(args, "-s", u.Shell)
	}
	if want := cmp.Or(u.Groups, u.AddGroups); want != nil {
		have := a.groupsOf(u.Name)
		n := len(changes)
		var add []string
		for _, g := range *want {
			if slices.Contains(have, g) {
				continue
			}
			add = append(add, g)
			line := "add to group " + g
			if _, ok := a.group(g); !ok {
				line += " (does not exist yet)"
			}
			changes = append(changes, line)
		}
		if u.Groups != nil {
			for _, g := range have {
				if !slices.Contains(*u.Groups, g) {
					changes = append(changes, "remove from group "+g)
				}
			}
		}
		switch {
		case len(changes) == n:
		case u.Groups != nil:
			args = append(args, "-G", strings.Join(*u.Groups, ","))
		default:
			args = append(args, "-a", "-G", strings.Join(add, ","))
		}
	}
	if u.Comment != "" && u.Comment != cur.comment {
		changes = append(changes, fmt.Sprintf("comment %q → %q", cur.comment, u.Comment))
		args = append(args, "-c", u.Comment)
	}
	if u.Password != "" {
		pw, err := shadowPassword(u.Name)
		if err != nil {
			return Result{}, "", "", err
		}
		if pw != u.Password {
			changes = append(changes, passwordChange(pw, u.Password))
			u.password = true
		}
	}
	if u.UID != "" && u.uid() != cur.uid || u.Home != "" && u.Home != cur.home {
		procs, err := userProcesses("/proc", cur.uid)
		if err != nil {
			return Result{}, "", "", err
		}
		if len(procs) > 0 {
			changes = append(changes, fmt.Sprintf("processes of %s run (%s); usermod fails while they run", u.Name, strings.Join(procs, ", ")))
		}
	}
	// usermod and chpasswd open /etc/passwd and /etc/shadow for any change.
	if len(args) > 1 || u.password {
		u.opens = append(u.opens, "/etc/passwd", "/etc/shadow")
	}
	if slices.Contains(args, "-G") {
		u.opens = append(u.opens, "/etc/group", "/etc/gshadow")
	}
	if len(args) > 1 {
		u.account = append(args, u.Name)
	}
	if len(changes) == 0 {
		return Result{Status: OK}, home, group, nil
	}
	return Result{Status: Change, Action: Modify, Changes: changes}, home, group, nil
}

// passwordChange describes the change of the password hash from cur to want.
// A lock or unlock keeps the hash; any other new hash is a change. passwd -S
// shows a hash that starts with "!" or "*" as locked.
func passwordChange(cur, want string) string {
	locked := func(pw string) bool { return strings.HasPrefix(pw, "!") || strings.HasPrefix(pw, "*") }
	switch {
	case !locked(cur) && (want == "!"+cur || want == "!" || want == "*"):
		return "lock the password"
	case !locked(want) && cur == "!"+want:
		return "unlock the password"
	}
	return "change password"
}

// checkShell fails when shell exists and is not an executable file. It
// returns a note for a shell that does not exist.
func checkShell(shell string) (string, error) {
	fi, err := os.Stat(shell)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return " (does not exist yet)", nil
	case err != nil:
		return "", err
	case !fi.Mode().IsRegular() || fi.Mode()&0o111 == 0:
		return "", fmt.Errorf("shell %s is not an executable file", shell)
	}
	return "", nil
}

// userProcesses returns the sorted names of the processes in the proc file
// system whose real, effective, or saved uid is uid, as usermod checks them.
// usermod skips a process in another root, such as a container.
func userProcesses(proc string, uid uint32) ([]string, error) {
	entries, err := os.ReadDir(proc)
	if err != nil {
		return nil, err
	}
	top, err := os.Stat("/")
	if err != nil {
		return nil, err
	}
	id := strconv.FormatUint(uint64(uid), 10)
	var names []string
	for _, e := range entries {
		if !numberRe.MatchString(e.Name()) {
			continue
		}
		root, err := os.Stat(path.Join(proc, e.Name(), "root"))
		var data []byte
		if err == nil {
			if !os.SameFile(root, top) {
				continue
			}
			data, err = os.ReadFile(path.Join(proc, e.Name(), "status"))
		}
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
			// The process ended.
			continue
		}
		if err != nil {
			return nil, err
		}
		var name string
		for line := range strings.Lines(string(data)) {
			key, value, _ := strings.Cut(strings.TrimSuffix(line, "\n"), ":\t")
			if key == "Name" {
				name = value
			}
			if key == "Uid" {
				if slices.Contains(strings.Fields(value)[:3], id) {
					names = append(names, name)
				}
				break
			}
		}
	}
	slices.Sort(names)
	return slices.Compact(names), nil
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

// group is the user's primary group after the step.
func (u *User) checkSSHD(ctx context.Context, sshConnection string, a accounts, cur passwdEntry, exists bool, home, group string) error {
	if _, err := os.Stat("/usr/sbin/sshd"); err != nil {
		return nil
	}
	spec, err := sshdSpec(u.Name, sshConnection)
	if err != nil {
		return err
	}
	out, err := run(ctx, nil, "sshd", "-T", "-C", spec)
	if err != nil {
		return err
	}
	conf := map[string]string{}
	for line := range strings.Lines(out) {
		key, value, _ := strings.Cut(strings.TrimSpace(line), " ")
		conf[key] = value
	}
	if u.AuthorizedKeys != nil {
		files := strings.Fields(conf["authorizedkeysfile"])
		if !slices.ContainsFunc(files, func(f string) bool {
			return f == ".ssh/authorized_keys" || f == "%h/.ssh/authorized_keys" || f == "~/.ssh/authorized_keys"
		}) {
			return fmt.Errorf("sshd reads the keys of %s from %s (AuthorizedKeysFile), not from ~/.ssh/authorized_keys", u.Name, conf["authorizedkeysfile"])
		}
		if conf["strictmodes"] == "yes" {
			if err := u.safeHome(a, cur, exists, home, group); err != nil {
				return err
			}
		}
	}
	if conf["usepam"] == "no" {
		// useradd locks the password of a new user.
		pw := "!"
		switch {
		case u.Password != "":
			pw = u.Password
		case exists:
			if pw, err = shadowPassword(u.Name); err != nil {
				return err
			}
		}
		if strings.HasPrefix(pw, "!") {
			return fmt.Errorf(`with UsePAM no, sshd refuses the login of %s: its password is locked with "!"`, u.Name)
		}
	}
	return nil
}

// safeHome fails when sshd with StrictModes ignores the keys in home after the
// step.
func (u *User) safeHome(a accounts, cur passwdEntry, exists bool, home, group string) error {
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
	if st.Mode&0o002 != 0 {
		return fmt.Errorf("with StrictModes yes, sshd ignores the keys of %s: others can write %s (mode %04o)", u.Name, home, st.Mode&0o7777)
	}
	owner := u.Name
	if st.Uid == 0 {
		owner = "root"
	}
	gid := st.Gid
	if g, ok := a.group(group); ok && exists && st.Uid != 0 && st.Gid == cur.gid {
		// usermod -g also changes the group of the user's home.
		gid = g.gid
	}
	if st.Mode&0o020 != 0 && !u.ownGroup(a, gid, group, owner) {
		return fmt.Errorf("with StrictModes yes, sshd ignores the keys of %s: the group %s can write %s (mode %04o) and is not the own group of %s alone", u.Name, a.groupName(gid), home, st.Mode&0o7777, u.Name)
	}
	return nil
}

// ownGroup reports whether Debian's sshd accepts a home of owner that the
// group gid can write. group is the user's primary group after the step.
func (u *User) ownGroup(a accounts, gid uint32, group, owner string) bool {
	g, ok := a.group(strconv.FormatUint(uint64(gid), 10))
	if !ok {
		return false
	}
	for _, o := range a.users {
		if o.gid == gid && o.name != u.Name {
			return false
		}
	}
	switch len(g.members) {
	case 0:
		pg, ok := a.group(group)
		return ok && pg.gid == gid
	case 1:
		return g.members[0] == owner
	}
	return false
}

// sshdSpec returns the connection spec of sshd -T for a login of user over
// the connection conn, a value of SSH_CONNECTION. Without UseDNS, sshd
// matches Host against the client address.
func sshdSpec(user, conn string) (string, error) {
	f := strings.Fields(conn)
	if len(f) != 4 || strings.Contains(conn, ",") {
		return "", fmt.Errorf("SSH_CONNECTION %q is not a client address and port and a local address and port", conn)
	}
	return fmt.Sprintf("user=%s,host=%s,addr=%s,laddr=%s,lport=%s", user, f[0], f[0], f[2], f[3]), nil
}

// shadowPassword returns the password hash of the user name in /etc/shadow.
func shadowPassword(name string) (string, error) {
	data, err := os.ReadFile("/etc/shadow")
	if err != nil {
		return "", err
	}
	var pw string
	err = rows("/etc/shadow", data, 9, func(f []string) error {
		if f[0] == name {
			pw = f[1]
		}
		return nil
	})
	return pw, err
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
	dirFi, err := dir.Stat(".")
	if err != nil {
		return nil, err
	}
	lines, err := prefixed(sshDir, dirFi, u.Name, group, 0o700)
	if err != nil {
		return nil, err
	}
	fi, exists, err := lstat(dir, "authorized_keys", nil)
	var keys []string
	switch {
	case err != nil:
		return nil, err
	case !exists:
		keys = append([]string{create[1]}, keyChanges(nil, *u.AuthorizedKeys)...)
	case fi.Mode()&fs.ModeSymlink != 0:
		target, _ := dir.Readlink("authorized_keys")
		keys = append([]string{fmt.Sprintf("replace the symbolic link %s to %s", file, target), create[1]}, keyChanges(nil, *u.AuthorizedKeys)...)
	case !fi.Mode().IsRegular():
		return nil, fmt.Errorf("%s is %s, not a file", file, kind(fi))
	default:
		keys, err = u.fileKeyLines(dir, file, fi, group)
		if err != nil {
			return nil, err
		}
	}
	lines = append(lines, keys...)
	if len(lines) == 0 {
		return nil, nil
	}
	// Apply writes authorized_keys through a rename in ~/.ssh.
	if err := noFlags(dir, ".", dirFi, sshDir); err != nil {
		return nil, err
	}
	if exists {
		if err := noFlags(dir, "authorized_keys", fi, file); err != nil {
			return nil, err
		}
	}
	return lines, nil
}

// fileKeyLines describes the changes of the key file fi in dir.
func (u *User) fileKeyLines(dir *os.Root, file string, fi fs.FileInfo, group string) ([]string, error) {
	lines, err := prefixed(file, fi, u.Name, group, 0o600)
	if err != nil {
		return nil, err
	}
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
	if string(data) == string(u.keyText()) {
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
	if u.missing {
		return fmt.Errorf("user %s does not exist", u.Name)
	}
	if u.account != nil {
		if _, err := run(ctx, nil, u.account[0], u.account[1:]...); err != nil {
			return err
		}
	}
	if u.password {
		// chpasswd reads the hash on stdin, so no command line shows it.
		if _, err := runInput(ctx, nil, u.Name+":"+u.Password+"\n", "chpasswd", "-e"); err != nil {
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
	return writeFile(dir, "authorized_keys", bytes.NewReader(u.keyText()), e.uid, e.gid, 0o600, func(tmp string) error {
		return dir.Rename(tmp, "authorized_keys")
	})
}
