package util

import (
	"encoding/base64"
	"os"
	"path/filepath"
)

type Marshaler interface {
	Marshal() ([]byte, error)
}

func saveDER(filename string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(filename)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	return os.WriteFile(filename+".der", data, perm)
}

func savePEM(filename string, data []byte, pemType string, perm os.FileMode) error {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer f.Close()

	header := "-----BEGIN " + pemType + "-----\n"
	footer := "-----END " + pemType + "-----\n"
	if _, err := f.WriteString(header); err != nil {
		return err
	}

	enc := base64.StdEncoding.EncodeToString(data)
	// 64文字ごとに改行
	for i := 0; i < len(enc); i += 64 {
		end := i + 64
		if end > len(enc) {
			end = len(enc)
		}
		if _, err := f.WriteString(enc[i:end] + "\n"); err != nil {
			return err
		}
	}
	if _, err := f.WriteString(footer); err != nil {
		return err
	}
	return nil
}

func marshalAndSaveWithType(filename string, marshaler Marshaler, pemType string, perm os.FileMode) error {
	data, err := marshaler.Marshal()
	if err != nil {
		return err
	}
	if err := saveDER(filename, data, perm); err != nil {
		return err
	}
	pemPath := filename + ".pem"
	if err := savePEM(pemPath, data, pemType, perm); err != nil {
		return err
	}
	return nil
}

func MarshalAndSaveCert(filename string, marshaler Marshaler) error {
	return marshalAndSaveWithType(filename, marshaler, "CERTIFICATE", 0644)
}

func MarshalAndSaveKey(filename string, marshaler Marshaler) error {
	return marshalAndSaveWithType(filename, marshaler, "PRIVATE KEY", 0600)
}
