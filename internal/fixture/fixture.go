// Package fixture gives tests access to the shared zone fixtures in the
// repository's top-level testdata directory (OSS-03 §7.1). The fixtures live
// at the repository root, not next to a Go package, so that non-Go consumers
// (e.g. the interop CI comparing against the reference implementation) can
// use the same files.
//
// The directory is located relative to this source file, so loading works
// from any package regardless of the test working directory. It is intended
// for `go test` runs inside the repository only.
package fixture

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Dir returns the absolute path of the repository's testdata directory.
func Dir() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("cannot locate fixture package source file")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata"), nil
}

// Read returns the contents of the named file in the testdata directory.
// The name must be a local path (no absolute paths or ".." traversal) so it
// cannot escape testdata.
func Read(filename string) ([]byte, error) {
	if !filepath.IsLocal(filename) {
		return nil, fmt.Errorf("fixture name %q must be a local path inside testdata", filename)
	}
	dir, err := Dir()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(dir, filename))
	if err != nil {
		return nil, fmt.Errorf("read fixture: %w", err)
	}
	return b, nil
}

// Zone returns the contents of the named zone fixture, e.g. "zone_full"
// resolves to testdata/zone_full.zone.
func Zone(name string) (string, error) {
	b, err := Read(name + ".zone")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
