package module

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/davidklassen/winch/internal/yamlx"
)

type Unit struct {
	Name      string    `yaml:"name,required" json:"name" line:"file name with its type" doc:"File name with its type, such as app.service or app@.service."`
	Source    string    `yaml:"source" json:"-" line:"file in the recipe's files/" doc:"File in the recipe's files/ directory. A step has source or content."`
	SourcePos yamlx.Pos `json:"-"`
	Content   *string   `yaml:"content" json:"-" line:"unit file text" doc:"Unit file text. A step has source or content."`
	// Data is the content, or the content of the source file in the recipe's
	// files.
	Data       []byte `json:"data"`
	DataSHA256 string `json:"data_sha256,omitempty"`
	Absent     bool   `yaml:"absent" json:"absent,omitempty" line:"stop the unit and remove it" doc:"Stop the unit, remove its enable links and its file, and run systemctl daemon-reload. For a template unit, it also stops each running instance and removes their enable links. The check fails when another unit file of the same name exists, such as one from a package."`

	// Check sets these for Apply.
	stop, links []string
	file        Module
}

func (*Unit) Noun() string { return "a unit step" }

func (u *Unit) Main() string { return u.Name }

// Path is the path of the unit file.
func (u *Unit) Path() string { return unitDir + "/" + u.Name }

func (u *Unit) Validate() error {
	if !unitRe.MatchString(u.Name) {
		return &yamlx.FieldError{Field: "name", Msg: fmt.Sprintf("%q is not a unit name", u.Name)}
	}
	i := strings.LastIndexByte(u.Name, '.')
	switch typ := u.Name[i+1:]; {
	case i < 0 || !slices.Contains(unitTypes, typ):
		return &yamlx.FieldError{Field: "name", Msg: fmt.Sprintf("%q needs a unit type, such as .service or .timer", u.Name)}
	case typ == "device" || typ == "scope":
		return &yamlx.FieldError{Field: "name", Msg: fmt.Sprintf("systemd does not load a .%s unit from a file", typ)}
	}
	stem := u.Name[:i]
	prefix, instance, at := strings.Cut(stem, "@")
	switch {
	case stem == "":
		return &yamlx.FieldError{Field: "name", Msg: fmt.Sprintf("%q needs a name before the type", u.Name)}
	case at && prefix == "":
		return &yamlx.FieldError{Field: "name", Msg: fmt.Sprintf("%q needs a name before \"@\"", u.Name)}
	case instance != "":
		return &yamlx.FieldError{Field: "name", Msg: fmt.Sprintf("%q is an instance; write the template %q, and put instance settings in a drop-in", u.Name, prefix+"@"+u.Name[i:])}
	case len(u.Name) > 255:
		return &yamlx.FieldError{Field: "name", Msg: fmt.Sprintf("has %d characters; a unit name has at most 255", len(u.Name))}
	}
	if u.Absent {
		return absentTakesNone(arg{"source", u.SourcePos.Line > 0}, arg{"content", u.Content != nil})
	}
	switch {
	case u.Content != nil && u.SourcePos.Line > 0:
		return &yamlx.FieldError{At: "content", Msg: "a unit step has at most one of content and source"}
	case u.Content != nil:
		return nil
	case u.SourcePos.Line > 0 && u.Source == "":
		return &yamlx.FieldError{Field: "source", Msg: "is empty"}
	case u.Source == "":
		return &yamlx.FieldError{Msg: "a unit step needs content or source"}
	}
	return CheckRelative("source", u.Source)
}

func (u *Unit) Text() ([]byte, string) { return u.Data, notText(u.Data) }

func (u *Unit) WithoutContent() Module {
	c := *u
	if u.Data != nil {
		c.DataSHA256 = sha(u.Data)
		c.Data = nil
	}
	return &c
}

// File is the file step that writes the unit file.
func (u *Unit) File() *File {
	return &File{Path: u.Path(), Data: u.Data, DataSHA256: u.DataSHA256, Absent: u.Absent}
}

func (u *Unit) Check(ctx context.Context, st *State, say Say) (Result, error) {
	if u.Absent {
		return u.checkAbsent(ctx, st, say)
	}
	fi, err := os.Lstat(u.Path())
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return Result{}, err
	case fi.Mode()&fs.ModeSymlink != 0:
		target, err := os.Readlink(u.Path())
		if err != nil {
			return Result{}, err
		}
		if target == "/dev/null" {
			return Result{}, fmt.Errorf("%s is masked; systemctl unmask %s removes the mask", u.Name, shellWord(u.Name))
		}
	case !fi.Mode().IsRegular():
		return Result{}, fmt.Errorf("%s is %s, not a file", u.Path(), kind(fi))
	}
	res, err := u.File().Check(ctx, st, say)
	if err != nil {
		return Result{}, err
	}
	// A run that wrote the file and then failed left systemd on the old unit.
	// systemctl show takes no template.
	if res.Status == OK {
		if strings.Contains(u.Name, "@") {
			return res, nil
		}
		out, err := run(ctx, "systemctl", "show", "--property=NeedDaemonReload", "--value", "--", u.Name)
		if err != nil {
			return Result{}, err
		}
		if strings.TrimSpace(out) != "yes" {
			return res, nil
		}
		res = Result{Status: Change, Action: Modify}
	}
	res.Changes = append(res.Changes, "daemon-reload")
	return res, nil
}

// checkAbsent finds the units to stop, the enable links, and the unit file.
func (u *Unit) checkAbsent(ctx context.Context, st *State, say Say) (Result, error) {
	var err error
	if u.file, err = u.fileStep(); err != nil {
		return Result{}, err
	}
	out, err := run(ctx, "systemctl", "show", "--property=UnitPath", "--value")
	if err != nil {
		return Result{}, err
	}
	for _, dir := range strings.Fields(out) {
		if dir == unitDir {
			continue
		}
		p := filepath.Join(dir, u.Name)
		_, err := os.Lstat(p)
		switch {
		case err == nil && u.file == nil:
			return Result{}, fmt.Errorf("%s has the unit file %s and none in %s; remove this step", u.Name, p, unitDir)
		case err == nil:
			return Result{}, fmt.Errorf("%s also has the unit file %s; remove %s with a file step to use it", u.Name, p, u.Path())
		case !errors.Is(err, fs.ErrNotExist):
			return Result{}, err
		}
	}
	if u.links, err = enableLinks(u.Name); err != nil {
		return Result{}, err
	}
	if u.file == nil && len(u.links) == 0 {
		return Result{Status: OK}, nil
	}
	units := []string{u.Name}
	if prefix, suffix, ok := strings.Cut(u.Name, "@"); ok {
		if units, err = instances(ctx, prefix+"@*"+suffix); err != nil {
			return Result{}, err
		}
	}
	var changes, triggers []string
	if len(units) > 0 {
		out, err := run(ctx, "systemctl", append([]string{"show", "--property=Id,LoadState,ActiveState,SubState,TriggeredBy", "--"}, units...)...)
		if err != nil {
			return Result{}, err
		}
		for block := range strings.SplitSeq(strings.TrimSuffix(out, "\n"), "\n\n") {
			s, err := parseShow(block)
			if err != nil {
				return Result{}, fmt.Errorf("systemctl show %s: %w", strings.Join(units, " "), err)
			}
			if s.up() || s.restarting() || s.active == "deactivating" {
				u.stop = append(u.stop, s.id)
				changes = append(changes, "stop "+s.id)
			}
			triggers = append(triggers, s.triggeredBy...)
		}
	}
	var startedBy []string
	if len(triggers) > 0 {
		slices.Sort(triggers)
		if startedBy, err = activeOrEnabled(ctx, slices.Compact(triggers)); err != nil {
			return Result{}, err
		}
	}
	var disabled []string
	for _, l := range u.links {
		disabled = append(disabled, filepath.Base(l))
	}
	if !strings.Contains(u.Name, "@") && len(disabled) > 0 {
		disabled = []string{u.Name}
	}
	slices.Sort(disabled)
	for _, n := range slices.Compact(disabled) {
		changes = append(changes, "disable "+n)
	}
	if u.file != nil {
		if _, err := u.file.Check(ctx, st, say); err != nil {
			return Result{}, err
		}
		changes = append(changes, "remove "+u.Path())
	}
	changes = append(changes, "daemon-reload")
	return Result{Status: Change, Action: Remove, Changes: changes, StartedBy: startedBy}, nil
}

// fileStep returns the step that removes what is at the unit's path: a file,
// or a symbolic link, as from systemctl link. It returns nil when there is
// nothing.
func (u *Unit) fileStep() (Module, error) {
	fi, err := os.Lstat(u.Path())
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, err
	case fi.Mode()&fs.ModeSymlink != 0:
		return &Link{Path: u.Path(), Absent: true}, nil
	case !fi.Mode().IsRegular():
		return nil, fmt.Errorf("%s is %s, not a file", u.Path(), kind(fi))
	}
	return u.File(), nil
}

func instances(ctx context.Context, pattern string) ([]string, error) {
	out, err := run(ctx, "systemctl", "list-units", "--all", "--plain", "--no-legend", "--full", "--", pattern)
	if err != nil {
		return nil, err
	}
	var units []string
	for line := range strings.Lines(out) {
		if f := strings.Fields(line); len(f) > 0 {
			units = append(units, f[0])
		}
	}
	return units, nil
}

func (u *Unit) Apply(ctx context.Context, say Say) error {
	if u.Absent {
		return u.applyAbsent(ctx, say)
	}
	if err := u.File().Apply(ctx, say); err != nil {
		return err
	}
	_, err := run(ctx, "systemctl", "daemon-reload")
	return err
}

func (u *Unit) applyAbsent(ctx context.Context, say Say) error {
	if len(u.stop) > 0 {
		if _, err := run(ctx, "systemctl", append([]string{"stop", "--"}, u.stop...)...); err != nil {
			return withJournal(ctx, u.stop[0], err)
		}
	}
	for _, l := range u.links {
		if err := os.Remove(l); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("disable %s: %w", u.Name, err)
		}
	}
	if u.file != nil {
		if err := u.file.Apply(ctx, say); err != nil {
			return err
		}
	}
	_, err := run(ctx, "systemctl", "daemon-reload")
	return err
}
