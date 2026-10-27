package module

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/davidklassen/winch/internal/yamlx"
)

type Line struct {
	Path   string `yaml:"path,required" json:"path"`
	Line   string `yaml:"line" json:"line,omitempty"`
	Match  string `yaml:"match,required" json:"match"`
	Absent bool   `yaml:"absent" json:"absent,omitempty"`
}

func (l *Line) Main() string { return l.Path }

func (l *Line) Validate() error {
	if err := checkPath(l.Path); err != nil {
		return err
	}
	if l.Match == "" {
		return &yamlx.FieldError{Field: "match", Msg: "must not be empty"}
	}
	re, err := regexp.Compile(l.Match)
	if err != nil {
		return &yamlx.FieldError{Field: "match", Msg: err.Error()}
	}
	switch {
	case l.Absent:
		return absentTakesNone(arg{"line", l.Line != ""})
	case l.Line == "":
		return &yamlx.FieldError{Field: "line", Msg: "a line step needs line, or absent: true"}
	case strings.ContainsAny(l.Line, "\n\r"):
		return &yamlx.FieldError{Field: "line", Msg: "must be one line"}
	case !re.MatchString(l.Line):
		return &yamlx.FieldError{Field: "line", Msg: "match does not find it, so each run would add it again"}
	}
	return nil
}

// Text returns the new line for the diff of the plan.
func (l *Line) Text() ([]byte, string) {
	if l.Absent {
		return nil, ""
	}
	return []byte(l.Line + "\n"), ""
}

func (l *Line) Check(ctx context.Context, _ *State, _ func(string)) (Result, error) {
	dir, missing, err := openParent(l.Path)
	if _, ok := errors.AsType[*noPathError](err); ok && l.Absent {
		return Result{Status: OK}, nil
	}
	if err != nil {
		return Result{}, err
	}
	defer dir.Close()
	name := path.Base(l.Path)
	fi, data, exists, err := l.read(dir, name, missing)
	switch {
	case err != nil:
		return Result{}, err
	case !exists && l.Absent:
		return Result{Status: OK}, nil
	case !exists:
		return Result{Status: Change, Action: Modify, Changes: []string{l.Path + " does not exist yet"}, Old: new("")}, nil
	}
	out, old, err := l.edit(data)
	if err != nil {
		return Result{}, err
	}
	if bytes.Equal(out, data) {
		return Result{Status: OK}, nil
	}
	if err := noFlags(dir, name, fi, l.Path); err != nil {
		return Result{}, err
	}
	res := Result{Status: Change, Action: Modify}
	if res.OldReason = notText([]byte(old)); res.OldReason == "" {
		res.Old = &old
	}
	return res, nil
}

func (l *Line) Apply(ctx context.Context, _ func(string)) error {
	dir, missing, err := openParent(l.Path)
	if err != nil {
		return err
	}
	defer dir.Close()
	name := path.Base(l.Path)
	fi, data, exists, err := l.read(dir, name, missing)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%s does not exist; line does not create a file", l.Path)
	}
	out, _, err := l.edit(data)
	if err != nil {
		return err
	}
	st := fi.Sys().(*syscall.Stat_t)
	return writeFile(dir, name, bytes.NewReader(out), st.Uid, st.Gid, uint32(st.Mode)&0o7777, func(tmp string) error {
		return dir.Rename(tmp, name)
	})
}

// read returns the info and the content of the file name in dir.
func (l *Line) read(dir *os.Root, name string, missing []string) (fs.FileInfo, []byte, bool, error) {
	fi, exists, err := lstat(dir, name, missing)
	if err != nil || !exists {
		return nil, nil, false, err
	}
	if !fi.Mode().IsRegular() {
		return nil, nil, false, fmt.Errorf("%s is %s, not a file", l.Path, kind(fi))
	}
	f, err := openSame(dir, name, fi)
	if err != nil {
		return nil, nil, false, err
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, nil, false, fmt.Errorf("read %s: %w", l.Path, err)
	}
	return fi, data, true, nil
}

// edit returns data with the step's change, and the old lines that the change
// replaces or removes, each with a newline.
func (l *Line) edit(data []byte) ([]byte, string, error) {
	re, err := regexp.Compile(l.Match)
	if err != nil {
		return nil, "", err
	}
	lines := strings.SplitAfter(string(data), "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	var out, old strings.Builder
	if l.Absent {
		for _, s := range lines {
			if t := strings.TrimSuffix(s, "\n"); re.MatchString(t) {
				old.WriteString(t + "\n")
			} else {
				out.WriteString(s)
			}
		}
		return []byte(out.String()), old.String(), nil
	}
	var found []int
	for i, s := range lines {
		if re.MatchString(strings.TrimSuffix(s, "\n")) {
			found = append(found, i)
		}
	}
	switch len(found) {
	case 0:
		out.Write(data)
		if len(data) > 0 && data[len(data)-1] != '\n' {
			out.WriteString("\n")
		}
		out.WriteString(l.Line + "\n")
	case 1:
		i := found[0]
		t := strings.TrimSuffix(lines[i], "\n")
		if t == l.Line {
			return data, "", nil
		}
		old.WriteString(t + "\n")
		lines[i] = l.Line + lines[i][len(t):]
		out.WriteString(strings.Join(lines, ""))
	default:
		nums := make([]string, len(found))
		for k, i := range found {
			nums[k] = strconv.Itoa(i + 1)
		}
		return nil, "", fmt.Errorf("%s has %d lines that match %q: lines %s", l.Path, len(found), l.Match, strings.Join(nums, ", "))
	}
	return []byte(out.String()), old.String(), nil
}
