package module

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"
)

// controllerOnly are the fields that the controller turns into other fields
// before it sends a step, and the fields that the helper sets.
var controllerOnly = map[string][]string{
	"certbot":  {"PendingHooks"},
	"dir":      {"ModePos"},
	"download": {"Recorded"},
	"file":     {"Content", "Template", "TemplatePos", "Source", "SourcePos"},
	"repo":     {"Key", "KeyPos", "KeyContent", "KeyContentPos"},
	"unit":     {"Source", "SourcePos", "Content"},
}

// fill sets every exported field of v to a value that is not zero.
func fill(t *testing.T, v reflect.Value) {
	t.Helper()
	switch v.Kind() {
	case reflect.String:
		v.SetString("x")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int:
		v.SetInt(7)
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		fill(t, v.Elem())
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		fill(t, v.Index(0))
	case reflect.Uint8:
		v.SetUint(7)
	case reflect.Struct:
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				fill(t, v.Field(i))
			}
		}
	default:
		t.Fatalf("fill: no value for kind %s", v.Kind())
	}
}

// spec: Modules; Remote execution/Helper
func TestArgsRoundTrip(t *testing.T) {
	for _, name := range Names() {
		t.Run(name, func(t *testing.T) {
			sent, _ := New(name)
			fill(t, reflect.ValueOf(sent).Elem())
			data, err := json.Marshal(sent)
			if err != nil {
				t.Fatal(err)
			}
			got, _ := New(name)
			if err := json.Unmarshal(data, got); err != nil {
				t.Fatal(err)
			}
			s, g := reflect.ValueOf(sent).Elem(), reflect.ValueOf(got).Elem()
			for i := range s.NumField() {
				f := s.Type().Field(i)
				if !f.IsExported() {
					continue
				}
				if slices.Contains(controllerOnly[name], f.Name) {
					if !g.Field(i).IsZero() {
						t.Errorf("%s reached the helper: %v", f.Name, g.Field(i))
					}
					continue
				}
				if !reflect.DeepEqual(s.Field(i).Interface(), g.Field(i).Interface()) {
					t.Errorf("%s: sent %v, the helper got %v (JSON %s)", f.Name, s.Field(i), g.Field(i), data)
				}
			}
		})
	}
}
