package sensitive

// Clear overwrites a byte slice after secret material is no longer needed.
// Go does not guarantee that every compiler or runtime copy is erased.
func Clear(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
