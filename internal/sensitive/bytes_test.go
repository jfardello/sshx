package sensitive

import "testing"

func TestClear(t *testing.T) {
	value := []byte("secret")
	Clear(value)
	for _, b := range value {
		if b != 0 {
			t.Fatal("byte slice was not cleared")
		}
	}
}
