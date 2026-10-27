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

	// Check sets the command for Apply.
	todo []string
}

func (g *Group) Main() string { return g.Name }

func (g *Group) Validate() error {
	if err := checkAccountName("name", "group", g.Name); err != nil {
		return err
	}
	return checkID("gid", g.GID)
}

var accountRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`)

// checkAccountName checks a user or a group name, as useradd and groupadd
// do without --badname.
func checkAccountName(field, what, name string) error {
	if !accountRe.MatchString(name) {
		return &yamlx.FieldError{Field: field, Msg: fmt.Sprintf(`%q is not a %s name; a name has lower-case letters, digits, "_", and "-", and starts with a letter or "_"`, name, what)}
	}
	if len(name) > 32 {
		return &yamlx.FieldError{Field: field, Msg: fmt.Sprintf("has %d characters; a name has at most 32", len(name))}
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

func (g *Group) Check(ctx context.Context, _ *State, _ func(string)) (Result, error) {
	a, err := readAccounts()
	if err != nil {
		return Result{}, err
	}
	cur, exists := a.group(g.Name)
	if g.GID != "" {
		other, ok := a.group(string(g.GID))
		if ok && other.name != g.Name {
			return Result{}, fmt.Errorf("gid %s belongs to group %s", g.GID, other.name)
		}
	}
	if !exists {
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
		return Result{Status: Change, Action: Create, Changes: changes}, nil
	}
	if gid, _ := strconv.ParseUint(string(g.GID), 10, 32); g.GID == "" || uint32(gid) == cur.gid {
		return Result{Status: OK}, nil
	}
	g.todo = []string{"groupmod", "-g", string(g.GID), g.Name}
	changes := []string{fmt.Sprintf("gid %d → %s; files keep the old gid", cur.gid, g.GID)}
	var users []string
	for _, u := range a.users {
		if u.gid == cur.gid {
			users = append(users, u.name)
		}
	}
	if len(users) > 0 {
		slices.Sort(users)
		changes = append(changes, fmt.Sprintf("the primary group of %s moves to gid %s", strings.Join(users, ", "), g.GID))
	}
	return Result{Status: Change, Action: Modify, Changes: changes}, nil
}

func (g *Group) Apply(ctx context.Context, _ func(string)) error {
	_, err := run(ctx, nil, g.todo[0], g.todo[1:]...)
	return err
}
