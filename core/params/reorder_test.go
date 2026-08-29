package params_test

import (
	"encoding/json"
	"sort"
)

// reorderJSON re-emits a parameter file with its keys in reverse order, so that
// a root which depended on file layout rather than on values would be caught.
func reorderJSON(raw []byte) []byte {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		panic(err)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))

	out := []byte("{")
	for i, k := range keys {
		if i > 0 {
			out = append(out, ',')
		}
		kb, _ := json.Marshal(k)
		out = append(out, kb...)
		out = append(out, ':')
		out = append(out, m[k]...)
	}
	return append(out, '}')
}
