package yamlx

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

// Decode fills the struct that v points to from n.
//
// Field tags: `yaml:"name"`, `yaml:"name,required"`, and `yaml:",key"`. A
// slice of structs with a ",key" field decodes from a map: each key goes into
// that field, in file order. A field `Pos Pos` gets the position of the
// struct, or of its key in such a map. A field `XPos Pos` gets the position
// of the value of field X. A field of type *Node gets the node
// as it is. After a struct decodes without errors, Decode calls its
// Validate() error method when it has one.
func Decode(n *Node, v any) error {
	d := decoder{}
	d.value(n, reflect.ValueOf(v).Elem(), "")
	return errors.Join(d.errs...)
}

// DecodeLazy is Decode for a value that can hold tagged scalars. It skips
// them, counts their keys as set, and skips Validate for a struct that holds
// one.
func DecodeLazy(n *Node, v any) error {
	d := decoder{lazy: true}
	d.value(n, reflect.ValueOf(v).Elem(), "")
	return errors.Join(d.errs...)
}

var (
	nodeType     = reflect.TypeFor[*Node]()
	posType      = reflect.TypeFor[Pos]()
	nameOrIDType = reflect.TypeFor[NameOrID]()
	idType       = reflect.TypeFor[ID]()
	// oneOrList are the slice types that also decode from one element.
	oneOrList = map[reflect.Type]string{
		reflect.TypeFor[Strings](): "a string or a list of strings",
		reflect.TypeFor[Ints]():    "an integer or a list of integers",
	}
)

type decoder struct {
	errs     []error
	lazy     bool
	deferred int
}

func (d *decoder) errorf(pos Pos, name, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if name != "" {
		msg = name + ": " + msg
	}
	d.errs = append(d.errs, &Error{Pos: pos, Msg: msg})
}

func (d *decoder) value(n *Node, v reflect.Value, name string) {
	if v.Type() == nodeType {
		v.Set(reflect.ValueOf(n))
		return
	}
	if n.Tag != "" && d.lazy {
		d.deferred++
		return
	}
	if n.Tag != "" {
		d.errorf(n.Pos, name, "%s is not allowed here", n.Tag)
		return
	}
	if what, ok := oneOrList[v.Type()]; ok {
		switch n.Kind {
		case List:
			d.slice(n, v, name)
		case Scalar:
			v.Set(reflect.MakeSlice(v.Type(), 1, 1))
			d.value(n, v.Index(0), name)
		default:
			d.errorf(n.Pos, name, "expected %s, got %s", what, Describe(n))
		}
		return
	}
	if _, ok := n.Value.(string); (v.Type() == nameOrIDType || v.Type() == idType) && n.Kind == Scalar && !ok {
		i, ok := n.Value.(int64)
		if !ok || i < 0 || n.Text != "" && !digitsRe.MatchString(n.Text) {
			msg := `must be a name or a numeric ID, such as "www-data" or "999"`
			if v.Type() == idType {
				msg = `must be a numeric ID, such as "1000"`
			}
			d.errorf(n.Pos, name, "%s", msg)
			return
		}
		v.SetString(strconv.FormatInt(i, 10))
		return
	}
	switch v.Kind() {
	case reflect.Pointer:
		if n.Kind == Null {
			return
		}
		p := reflect.New(v.Type().Elem())
		d.value(n, p.Elem(), name)
		v.Set(p)
	case reflect.String:
		s, ok := n.Value.(string)
		if !ok {
			hint := ""
			if n.Kind == Scalar {
				hint = "; quote the value to make it a string"
			}
			d.errorf(n.Pos, name, "expected a string, got %s%s", Describe(n), hint)
			return
		}
		v.SetString(s)
	case reflect.Bool:
		b, ok := n.Value.(bool)
		if !ok {
			d.errorf(n.Pos, name, "expected true or false, got %s", Describe(n))
			return
		}
		v.SetBool(b)
	case reflect.Int, reflect.Int64:
		i, ok := n.Value.(int64)
		if !ok {
			d.errorf(n.Pos, name, "expected an integer, got %s", Describe(n))
			return
		}
		v.SetInt(i)
	case reflect.Slice:
		d.slice(n, v, name)
	case reflect.Struct:
		d.strct(n, v, name)
	default:
		panic(fmt.Sprintf("yamlx: cannot decode into %s", v.Type()))
	}
}

func (d *decoder) slice(n *Node, v reflect.Value, name string) {
	elem := v.Type().Elem()
	if key := keyField(elem); key >= 0 {
		if n.Kind != Map {
			d.errorf(n.Pos, name, "expected a map, got %s", Describe(n))
			return
		}
		out := reflect.MakeSlice(v.Type(), len(n.Pairs), len(n.Pairs))
		for i, p := range n.Pairs {
			e := out.Index(i)
			e.Field(key).SetString(p.Key)
			d.strct(p.Value, e, p.Key)
			if f := e.FieldByName("Pos"); f.IsValid() && f.Type() == posType {
				f.Set(reflect.ValueOf(p.KeyPos))
			}
		}
		v.Set(out)
		return
	}
	if n.Kind != List {
		d.errorf(n.Pos, name, "expected a list, got %s", Describe(n))
		return
	}
	out := reflect.MakeSlice(v.Type(), len(n.Items), len(n.Items))
	for i, item := range n.Items {
		d.value(item, out.Index(i), name)
	}
	v.Set(out)
}

type field struct {
	index    int
	name     string
	required bool
}

func fields(t reflect.Type) []field {
	var out []field
	for i := range t.NumField() {
		tag, ok := t.Field(i).Tag.Lookup("yaml")
		if !ok || tag == "-" {
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		if name == "" {
			continue
		}
		out = append(out, field{index: i, name: name, required: opts == "required"})
	}
	return out
}

func keyField(t reflect.Type) int {
	if t.Kind() != reflect.Struct {
		return -1
	}
	for i := range t.NumField() {
		if t.Field(i).Tag.Get("yaml") == ",key" {
			return i
		}
	}
	return -1
}

func (d *decoder) strct(n *Node, v reflect.Value, name string) {
	if n.Kind != Map && n.Kind != Null {
		d.errorf(n.Pos, name, "expected a map, got %s", Describe(n))
		return
	}
	if f := v.FieldByName("Pos"); f.IsValid() && f.Type() == posType {
		f.Set(reflect.ValueOf(n.Pos))
	}
	before, deferred := len(d.errs), d.deferred
	fs := fields(v.Type())
	seen := map[string]Pos{}
	for _, p := range n.Pairs {
		i := slices.IndexFunc(fs, func(f field) bool { return f.name == p.Key })
		if i < 0 {
			var names []string
			for _, f := range fs {
				names = append(names, f.name)
			}
			d.errorf(p.KeyPos, "", "unknown key %q%s", p.Key, Suggest(p.Key, names))
			continue
		}
		seen[p.Key] = p.Value.Pos
		d.value(p.Value, v.Field(fs[i].index), p.Key)
		if f := v.FieldByName(v.Type().Field(fs[i].index).Name + "Pos"); f.IsValid() && f.Type() == posType {
			f.Set(reflect.ValueOf(p.Value.Pos))
		}
	}
	for _, f := range fs {
		if _, ok := seen[f.name]; f.required && !ok {
			d.errorf(n.Pos, "", "missing key %q", f.name)
		}
	}
	if len(d.errs) > before || d.deferred > deferred {
		return
	}
	val, ok := v.Addr().Interface().(interface{ Validate() error })
	if !ok {
		return
	}
	err := val.Validate()
	if err == nil {
		return
	}
	if fe, ok := errors.AsType[*FieldError](err); ok {
		pos, ok := seen[fe.Field]
		if !ok {
			pos = n.Pos
		}
		d.errorf(pos, fe.Field, "%s", fe.Msg)
		return
	}
	d.errorf(n.Pos, "", "%s", err)
}

// Strings decodes from one string or a list of strings.
type Strings []string

// Ints decodes from one integer or a list of integers.
type Ints []int

// NameOrID decodes from a string, or from an integer that is not negative.
// The integer gives its decimal digits. An integer from a file must be written
// as plain digits.
type NameOrID string

// ID decodes as NameOrID does. The module checks that a string holds only
// digits.
type ID string
