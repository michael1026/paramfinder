package util

import (
	"bytes"
	"encoding/json"
	"math/rand"
)

var letters = []rune("abcdefghijklmnopqrstuvwxyz")

func AppendIfMissing(slice []string, s string) []string {
	for _, ele := range slice {
		if ele == s {
			return slice
		}
	}
	return append(slice, s)
}

func RandSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func JSONMarshal(t interface{}) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(t)
	return buffer.Bytes(), err
}

func SplitMap(m map[string]string) (odds map[string]string, evens map[string]string) {
	n := 1
	odds = make(map[string]string)
	evens = make(map[string]string)
	for key, value := range m {
		if n%2 == 0 {
			evens[key] = value
		} else {
			odds[key] = value
		}
		n++
	}
	return odds, evens
}

func DeleteByKey(m *map[string]string, val string) {
	for k, v := range *m {
		if v == val {
			delete(*m, k)
		}
	}
}
