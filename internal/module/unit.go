package module

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"

	"github.com/davidklassen/winch/internal/yamlx"
)

type Unit struct {
	Name      string    `yaml:"name,required" json:"name" doc:"The unit file name with its type, such as app.service or app@.service."`
	Source    string    `yaml:"source" json:"-" doc:"A file in the recipe's files directory. A step has source or content."`
	SourcePos yamlx.Pos `json:"-"`
	Content   *string   `yaml:"content" json:"-" doc:"The content of the unit file. A step has source or content."`
	// Data is the content, or the content of the source file in the recipe's
	// files.
	Data       []byte `json:"data"`
	DataSHA256 string `json:"data_sha256,omitempty"`
}

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
	switch {
	case u.Content != nil && u.SourcePos.Line > 0:
		return &yamlx.FieldError{Field: "content", Msg: "a unit has only one of content and source"}
	case u.Content != nil:
		return nil
	case u.SourcePos.Line > 0 && u.Source == "":
		return &yamlx.FieldError{Field: "source", Msg: "must not be empty"}
	case u.Source == "":
		return &yamlx.FieldError{Field: "content", Msg: "a unit needs content or source"}
	}
	return checkRelative("source", u.Source)
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
	return &File{Path: u.Path(), Data: u.Data, DataSHA256: u.DataSHA256}
}

func (u *Unit) Check(ctx context.Context, st *State, note func(string)) (Result, error) {
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
			return Result{}, fmt.Errorf("%s is masked; systemctl unmask %s removes the mask", u.Name, u.Name)
		}
	case !fi.Mode().IsRegular():
		return Result{}, fmt.Errorf("%s is %s, not a file", u.Path(), kind(fi))
	}
	res, err := u.File().Check(ctx, st, note)
	if err != nil {
		return Result{}, err
	}
	// A run that wrote the file and then failed left systemd on the old unit.
	// systemctl show takes no template.
	if res.Status == OK {
		if strings.Contains(u.Name, "@") {
			return res, nil
		}
		out, err := run(ctx, nil, "systemctl", "show", "--property=NeedDaemonReload", "--value", "--", u.Name)
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

func (u *Unit) Apply(ctx context.Context, note func(string)) error {
	if err := u.File().Apply(ctx, note); err != nil {
		return err
	}
	_, err := run(ctx, nil, "systemctl", "daemon-reload")
	return err
}
