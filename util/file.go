package util

import (
	"os"
	"path/filepath"
)

type Marshaler interface {
	Marshal() ([]byte, error)
}

func MarshalAndSave(filename string, marshaler Marshaler, perm os.FileMode) error {
	data, err := marshaler.Marshal()
	if err != nil {
		return err
	}

	dir := filepath.Dir(filename)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	return os.WriteFile(filename, data, perm)
}
