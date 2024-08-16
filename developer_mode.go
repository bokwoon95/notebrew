//go:build dev
// +build dev

package notebrew

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func init() {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("developer mode enabled but cannot determine source file location.")
	}
	if strings.HasPrefix(file, "github.com") {
		fmt.Printf("developer mode: source root directory determined to be %s which is likely wrong and will cause problems. Please check if -trimpath flag was used in building the binary.\n", filepath.Dir(file))
	}
	RuntimeFS = os.DirFS(filepath.Dir(file))
	developerMode = true
}
