package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestInotifySetupRaisesSharedQuotaAndNeverLowersHigherValues(t *testing.T) {
	for _, initial := range []int{11955, 1048576} {
		t.Run(strconv.Itoa(initial), func(t *testing.T) {
			dir := t.TempDir()
			value, config := filepath.Join(dir, "limit"), filepath.Join(dir, "sysctl.conf")
			os.WriteFile(value, []byte(strconv.Itoa(initial)), 0600)
			mock := "#!/bin/sh\nset -eu\ntest \"$1\" = -p\nawk -F '= *' '/^fs.inotify.max_user_watches/{print $2}' \"$2\" > \"$WEBSCAN_TEST_VALUE\"\n"
			os.WriteFile(filepath.Join(dir, "sysctl"), []byte(mock), 0700)
			run := func() {
				cmd := exec.Command("bash", "-se")
				cmd.Stdin = strings.NewReader(inotifyTuningScript(value, config))
				cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "WEBSCAN_TEST_VALUE="+value)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatal(err, string(out))
				}
			}
			run()
			b, _ := os.ReadFile(value)
			want := strconv.Itoa(max(initial, minimumInotifyWatches))
			if strings.TrimSpace(string(b)) != want {
				t.Fatal("quota not raised or higher quota lowered", string(b))
			}
			before, _ := os.Stat(config)
			run()
			after, _ := os.Stat(config)
			if !before.ModTime().Equal(after.ModTime()) || after.Mode().Perm() != 0644 {
				t.Fatal("unchanged persistent setting rewritten or wrong permissions")
			}
		})
	}
}

func TestInotifySetupRejectsSymlinkAndFailedKernelApplication(t *testing.T) {
	dir := t.TempDir()
	value, config := filepath.Join(dir, "limit"), filepath.Join(dir, "sysctl.conf")
	os.WriteFile(value, []byte("11955"), 0600)
	os.WriteFile(filepath.Join(dir, "sysctl"), []byte("#!/bin/sh\nexit 1\n"), 0700)
	run := func() error {
		cmd := exec.Command("bash", "-se")
		cmd.Stdin = strings.NewReader(inotifyTuningScript(value, config))
		cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
		_, err := cmd.CombinedOutput()
		return err
	}
	if run() == nil {
		t.Fatal("kernel application failure ignored")
	}
	os.Remove(config)
	os.Symlink(value, config)
	if run() == nil {
		t.Fatal("symlink configuration followed")
	}
	b, _ := os.ReadFile(value)
	if string(b) != "11955" {
		t.Fatal("symlink target changed")
	}
}
