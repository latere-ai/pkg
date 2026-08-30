// Package syncmap provides a type-safe generic wrapper around sync.Map.
//
// The stdlib sync.Map uses any for keys and values, requiring a type assertion
// at every call site. [Map] wraps it with generics for compile-time type safety
// on Store, Load, and Delete. The zero value is ready to use, matching sync.Map
// semantics.
//
// # Usage
//
//	var m syncmap.Map[string, *Connection]
//	m.Store("key", conn)
//	if val, ok := m.Load("key"); ok { ... }
package syncmap
