package gateway

import (
	"os"
)

func writeTestFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

func testReadFile(p string) ([]byte, error) {
	return os.ReadFile(p)
}
