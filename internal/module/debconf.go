package module

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"unicode"

	"github.com/davidklassen/winch/internal/yamlx"
)

type Debconf struct {
	Package  string `yaml:"package,required" json:"package" line:"package that asks the question" doc:"Package that asks the question."`
	Question string `yaml:"question,required" json:"question" line:"name, such as postfix/main_mailer_type" doc:"Name, such as postfix/main_mailer_type."`
	Type     string `yaml:"type,required" json:"type" line:"question type, such as string, boolean, or select" doc:"Question type, such as string, boolean, or select."`
	Value    string `yaml:"value,required" json:"value" line:"answer, as text" doc:"Answer, as text. Only the scripts of the package read it, so put the step before the pkg step that installs the package."`
}

func (d *Debconf) Main() string { return d.Question }

var debconfTypes = []string{"string", "password", "boolean", "select", "multiselect"}

func (d *Debconf) Validate() error {
	if !pkgNameRe.MatchString(d.Package) {
		return &yamlx.FieldError{Field: "package", Msg: fmt.Sprintf("%q is not a package name", d.Package)}
	}
	if d.Question == "" {
		return &yamlx.FieldError{Field: "question", Msg: "is empty"}
	}
	if hasSpace(d.Question) {
		return &yamlx.FieldError{Field: "question", Msg: spaceMsg}
	}
	if !slices.Contains(debconfTypes, d.Type) {
		return &yamlx.FieldError{Field: "type", Msg: fmt.Sprintf("%q is not a type; use string, password, boolean, select, or multiselect", d.Type)}
	}
	if strings.ContainsFunc(d.Value, unicode.IsControl) {
		return &yamlx.FieldError{Field: "value", Msg: "has a control character, such as a newline"}
	}
	if d.Type == "boolean" && d.Value != "true" && d.Value != "false" {
		return &yamlx.FieldError{Field: "value", Msg: `a boolean answer is "true" or "false"`}
	}
	return nil
}

// Check reads the answer and the template of the question while it holds the
// dpkg locks, so no apt run changes them. A changed answer of an installed
// package gives a note.
func (d *Debconf) Check(ctx context.Context, _ *State, note func(string)) (Result, error) {
	unlock, err := lockFiles(ctx, dpkgLocks, note)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	// debconf-communicate exits with the status of the last command, which
	// VERSION keeps at 0.
	q := d.Question
	out, err := runInput(ctx, aptEnv, "GET "+q+"\nMETAGET "+q+" type\nMETAGET "+q+" choices-c\nMETAGET "+q+" choices\nMETAGET "+q+" description\nVERSION 2.0\n", "debconf-communicate")
	if err != nil {
		return Result{}, err
	}
	// Each command gives one line: a status code, a space, and the value.
	var codes, values [6]string
	for i, line := range strings.SplitN(strings.TrimSuffix(out, "\n"), "\n", 6) {
		codes[i], values[i], _ = strings.Cut(line, " ")
	}
	cur, exists := values[0], codes[0] == "0"
	// debconf-set-selections makes a dummy template for a question that no
	// package has loaded.
	if exists && values[4] != "Dummy template" {
		if codes[1] == "0" && values[1] != d.Type {
			return Result{}, fmt.Errorf("%s is a %s question, not %s", d.Question, values[1], d.Type)
		}
		choices := ""
		switch {
		case codes[2] == "0" && values[2] != "":
			choices = values[2]
		case codes[3] == "0":
			choices = values[3]
		}
		if err := d.checkChoices(splitChoices(choices)); err != nil {
			return Result{}, err
		}
	}
	if exists && sameAnswer(d.Type, cur, d.Value) {
		return Result{Status: OK}, nil
	}
	// dpkg-query fails for a package that dpkg does not know.
	status, err := run(ctx, nil, "dpkg-query", "-W", "-f=${db:Status-Status}\n", d.Package)
	if err != nil && !errors.As(err, new(*exec.ExitError)) {
		return Result{}, err
	}
	if slices.Contains(strings.Fields(status), "installed") {
		note(d.Package + " is installed; the new answer has no effect until dpkg-reconfigure runs")
	}
	action, old := Modify, fmt.Sprintf("%q", cur)
	if !exists {
		action, old = Create, "(none)"
	}
	line := "answer " + old + " → " + fmt.Sprintf("%q", d.Value)
	if d.Type == "password" {
		line = "answer (password, not shown)"
	}
	return Result{Status: Change, Action: action, Changes: []string{line}}, nil
}

// checkChoices fails on a select or multiselect value that is not one of the
// known choices.
func (d *Debconf) checkChoices(choices []string) error {
	// A choice such as ${locales} gets its values from the package's
	// scripts; it is empty before they run.
	if len(choices) == 0 || d.Type != "select" && d.Type != "multiselect" || slices.Contains(choices, "") {
		return nil
	}
	values := []string{d.Value}
	if d.Type == "multiselect" {
		values = splitChoices(d.Value)
	}
	for _, v := range values {
		if !slices.Contains(choices, v) {
			return fmt.Errorf("%q is not a choice of %s; the choices are %s", v, d.Question, strings.Join(choices, ", "))
		}
	}
	return nil
}

func (d *Debconf) Apply(ctx context.Context, note func(string)) error {
	unlock, err := lockFiles(ctx, dpkgLocks, note)
	if err != nil {
		return err
	}
	defer unlock()
	_, err = runInput(ctx, aptEnv, d.Package+" "+d.Question+" "+d.Type+" "+d.Value+"\n", "debconf-set-selections")
	return err
}

// splitChoices splits a list of debconf choices at ", ". "\," is a comma in
// a choice.
func splitChoices(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s) && s[i+1] == ',':
			cur.WriteByte(',')
			i++
		case s[i] == ',':
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(s[i])
		}
	}
	return append(out, strings.TrimSpace(cur.String()))
}

// sameAnswer compares two answers of a question of the type typ. A
// multiselect answer is a set.
func sameAnswer(typ, a, b string) bool {
	if typ != "multiselect" {
		return a == b
	}
	x, y := splitChoices(a), splitChoices(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}
