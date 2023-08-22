package util

// To avoid having to use experimental library imports, the below is taken from https://cs.opensource.google/go/x/exp/+/master:maps/maps.go
// Keys returns the keys of the map m.
// The keys will be in an indeterminate order
func MapKeys[M ~map[K]V, K comparable, V any](m M) []K {
	r := make([]K, 0, len(m))
	for k := range m {
		r = append(r, k)
	}
	return r
}
