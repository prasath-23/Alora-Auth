package shared

import (
	"reflect"
	"strings"
	"unicode/utf8"
)

// Storable reports whether s is text PostgreSQL can store: valid UTF-8 with no
// NUL character. Every id, name and search term the API is given ends up as a
// text value in the database, where anything else is an error — so wherever
// such text arrives (a path, a query, a body, a form, a credential) it is the
// caller's mistake, answered with a 400, never a server error.
func Storable(s string) bool {
	return utf8.ValidString(s) && strings.IndexByte(s, 0) < 0
}

// AllStorable reports whether every string in ss is Storable.
func AllStorable(ss []string) bool {
	for _, s := range ss {
		if !Storable(s) {
			return false
		}
	}
	return true
}

// storableValue reports whether every string reachable from v — fields,
// elements, map keys and values, through pointers and interfaces — is Storable.
func storableValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.String:
		return Storable(v.String())
	case reflect.Pointer, reflect.Interface:
		return v.IsNil() || storableValue(v.Elem())
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() && !storableValue(v.Field(i)) {
				return false
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if !storableValue(v.Index(i)) {
				return false
			}
		}
	case reflect.Map:
		it := v.MapRange()
		for it.Next() {
			if !storableValue(it.Key()) || !storableValue(it.Value()) {
				return false
			}
		}
	}
	return true
}
