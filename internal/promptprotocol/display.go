package promptprotocol

import (
	"strconv"
	"strings"
)

// DisplayText preserves the whole value as visible ASCII, escaping controls,
// Unicode (including bidi), markup delimiters, quotes and backslashes. It does
// not truncate. Selection display fields carry this representation on the wire.
func DisplayText(value string) string {
	quoted := strconv.QuoteToASCII(value)
	return strings.NewReplacer("<", `\u003c`, ">", `\u003e`, "&", `\u0026`, "'", `\u0027`).Replace(quoted[1 : len(quoted)-1])
}

func canonicalDisplay(value string) bool {
	decoded, err := strconv.Unquote(`"` + value + `"`)
	return err == nil && DisplayText(decoded) == value
}
