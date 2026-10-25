package yamlx

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
)

// Value returns n as a Go value: nil, string, bool, int, float64, []any, or
// map[string]any. A tagged scalar gives its Value as it is.
func Value(n *Node) any {
	switch n.Kind {
	case Scalar:
		if i, ok := n.Value.(int64); ok {
			return int(i)
		}
		return n.Value
	case Map:
		m := make(map[string]any, len(n.Pairs))
		for _, p := range n.Pairs {
			m[p.Key] = Value(p.Value)
		}
		return m
	case List:
		l := make([]any, len(n.Items))
		for i, item := range n.Items {
			l[i] = Value(item)
		}
		return l
	}
	return nil
}

// FromValue returns a Go value as a node at pos. Map keys must be strings;
// they go in sorted order.
func FromValue(v any, pos Pos) (*Node, error) {
	n := &Node{Pos: pos}
	if v == nil {
		return n, nil
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.String:
		n.Kind, n.Value = Scalar, rv.String()
	case reflect.Bool:
		n.Kind, n.Value = Scalar, rv.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n.Kind, n.Value = Scalar, rv.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n.Kind, n.Value = Scalar, int64(rv.Uint())
	case reflect.Float32, reflect.Float64:
		n.Kind, n.Value = Scalar, rv.Float()
	case reflect.Slice, reflect.Array:
		n.Kind = List
		for i := range rv.Len() {
			item, err := FromValue(rv.Index(i).Interface(), pos)
			if err != nil {
				return nil, err
			}
			n.Items = append(n.Items, item)
		}
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			return nil, fmt.Errorf("a map key must be a string, got %s", rv.Type().Key())
		}
		n.Kind = Map
		keys := rv.MapKeys()
		slices.SortFunc(keys, func(a, b reflect.Value) int { return strings.Compare(a.String(), b.String()) })
		for _, k := range keys {
			item, err := FromValue(rv.MapIndex(k).Interface(), pos)
			if err != nil {
				return nil, err
			}
			n.Pairs = append(n.Pairs, Pair{Key: k.String(), KeyValue: k.String(), KeyPos: pos, Value: item})
		}
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return n, nil
		}
		return FromValue(rv.Elem().Interface(), pos)
	default:
		return nil, fmt.Errorf("cannot use a value of type %s", rv.Type())
	}
	return n, nil
}
