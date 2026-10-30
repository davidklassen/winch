package module

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/davidklassen/winch/internal/yamlx"
)

type Group struct {
	Name   string   `yaml:"name,required" json:"name"`
	GID    yamlx.ID `yaml:"gid" json:"gid,omitempty"`
	System bool     `yaml:"system" json:"system,omitempty"`
	Absent bool     `yaml:"absent" json:"absent,omitempty"`

	// Check sets the command for Apply.
	todo []string
}

func (g *Group) Main() string { return g.Name }

func (g *Group) Validate() error {
	if err := checkAccountName("name", "group", g.Name); err != nil {
		return err
	}
	if g.Absent {
		return absentTakesNone(arg{"gid", g.GID != ""}, arg{"system", g.System})
	}
	return checkID("gid", g.GID)
}

// An account that exists may have a name such as Debian-exim; winch creates
// only newAccountRe names.
var (
	accountRe    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)
	newAccountRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`)
)

func checkAccountName(field, what, name string) error {
	if !accountRe.MatchString(name) {
		return &yamlx.FieldError{Field: field, Msg: fmt.Sprintf(`%q is not a %s name; a name has letters, digits, "_", ".", and "-", and starts with a letter or "_"`, name, what)}
	}
	if len(name) > 32 {
		return &yamlx.FieldError{Field: field, Msg: fmt.Sprintf("has %d characters; a name has at most 32", len(name))}
	}
	return nil
}

func checkNewAccount(what, name string) error {
	if !newAccountRe.MatchString(name) {
		return fmt.Errorf(`%s %s does not exist, and winch creates only names with lower-case letters, digits, "_", and "-" that start with a letter or "_"`, what, name)
	}
	return nil
}

// checkID checks a numeric ID. chown takes the ID 4294967295 as "no
// change".
func checkID(field string, id yamlx.ID) error {
	if id == "" {
		return nil
	}
	if !numberRe.MatchString(string(id)) {
		return &yamlx.FieldError{Field: field, Msg: `must be a numeric ID, such as "1000"`}
	}
	if n, err := strconv.ParseUint(string(id), 10, 32); err != nil || n == math.MaxUint32 {
		return &yamlx.FieldError{Field: field, Msg: "an ID must be below 4294967295"}
	}
	return nil
}

func (g *Group) Check(ctx context.Context, st *State, _ func(string)) (Result, error) {
	a, err := readAccounts()
	if err != nil {
		return Result{}, err
	}
	cur, exists := a.group(g.Name)
	if g.Absent {
		return g.checkAbsent(a, cur, exists, st)
	}
	if g.GID != "" {
		other, ok := a.group(string(g.GID))
		if ok && other.name != g.Name {
			return Result{}, fmt.Errorf("gid %s belongs to group %s", g.GID, other.name)
		}
	}
	if !exists {
		if err := checkNewAccount("group", g.Name); err != nil {
			return Result{}, err
		}
		var changes []string
		g.todo = []string{"groupadd"}
		if g.GID != "" {
			changes = append(changes, "gid "+string(g.GID))
			g.todo = append(g.todo, "-g", string(g.GID))
		}
		if g.System {
			changes = append(changes, "system group")
			g.todo = append(g.todo, "-r")
		}
		g.todo = append(g.todo, g.Name)
		if err := noFlagsAt("/etc/group", "/etc/gshadow"); err != nil {
			return Result{}, err
		}
		return Result{Status: Change, Action: Create, Changes: changes}, nil
	}
	if gid, _ := strconv.ParseUint(string(g.GID), 10, 32); g.GID == "" || uint32(gid) == cur.gid {
		return Result{Status: OK}, nil
	}
	if err := noFlagsAt("/etc/passwd", "/etc/group"); err != nil {
		return Result{}, err
	}
	g.todo = []string{"groupmod", "-g", string(g.GID), g.Name}
	changes := []string{fmt.Sprintf("gid %d → %s; files keep the old gid", cur.gid, g.GID)}
	if users := a.primaryUsers(cur.gid); len(users) > 0 {
		changes = append(changes, fmt.Sprintf("the primary group of %s moves to gid %s", strings.Join(users, ", "), g.GID))
	}
	return Result{Status: Change, Action: Modify, Changes: changes}, nil
}

func (g *Group) checkAbsent(a accounts, cur groupEntry, exists bool, st *State) (Result, error) {
	if !exists {
		return Result{Status: OK}, nil
	}
	if err := g.removable(a, cur, st); err != nil {
		return Result{}, err
	}
	if err := noFlagsAt("/etc/group", "/etc/gshadow"); err != nil {
		return Result{}, err
	}
	g.todo = []string{"groupdel", g.Name}
	return Result{Status: Change, Action: Remove}, nil
}

func (g *Group) removable(a accounts, cur groupEntry, st *State) error {
	if login, ok := a.userByID(st.LoginUID); st.LoginUID != 0 && ok && (login.gid == cur.gid || slices.Contains(cur.members, login.name)) {
		return fmt.Errorf("the login user %s is in group %s; removing it cuts off winch's access", login.name, g.Name)
	}
	users := slices.DeleteFunc(a.primaryUsers(cur.gid), func(u string) bool { return slices.Contains(st.RemovedUsers, u) })
	if len(users) > 0 {
		return fmt.Errorf("%s is the primary group of %s; remove them or change their group first", g.Name, strings.Join(users, ", "))
	}
	return nil
}

// primaryUsers returns the sorted names of the users whose primary group is gid.
func (a accounts) primaryUsers(gid uint32) []string {
	var users []string
	for _, u := range a.users {
		if u.gid == gid {
			users = append(users, u.name)
		}
	}
	slices.Sort(users)
	return users
}

func (g *Group) Apply(ctx context.Context, _ func(string)) error {
	_, err := run(ctx, nil, g.todo[0], g.todo[1:]...)
	return err
}
