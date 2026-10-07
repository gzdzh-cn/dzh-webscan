package main

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
	"webscan/internal/common"
)

func TestMenuActions(t *testing.T) {
	for _, tc := range []struct{ input, action string }{{"1\n", "--install"}, {"2\n", "--reinstall"}, {"3\n1\n", "--uninstall"}, {"bad\n 3 \n1\n", "--uninstall"}} {
		var out bytes.Buffer
		got, err := selectAction([]string{"--config", "test.yaml"}, strings.NewReader(tc.input), &out)
		if err != nil || got[len(got)-1] != tc.action || !strings.Contains(out.String(), "3、卸载") {
			t.Fatalf("selection: %v %v", got, err)
		}
	}
	if _, err := selectAction(nil, strings.NewReader("0\n"), new(bytes.Buffer)); !errors.Is(err, errMenuExit) {
		t.Fatal(err)
	}
	if _, err := selectAction(nil, strings.NewReader(""), new(bytes.Buffer)); err == nil {
		t.Fatal("EOF must not install")
	}
}

func TestExplicitActionSkipsMenu(t *testing.T) {
	for _, flag := range []string{"--install", "--reinstall", "--uninstall", "--dry-run", "--help", "--resume"} {
		var out bytes.Buffer
		args := []string{flag, "--non-interactive"}
		got, err := selectAction(args, strings.NewReader(""), &out)
		if err != nil || !reflect.DeepEqual(got, args) || out.Len() != 0 {
			t.Fatalf("%s: %v %v", flag, got, err)
		}
	}
	got, err := selectAction([]string{"--non-interactive"}, strings.NewReader(""), new(bytes.Buffer))
	if err != nil || got[len(got)-1] != "--install" {
		t.Fatal(got, err)
	}
}

func TestValidateActions(t *testing.T) {
	for _, args := range [][]string{{"--add-node"}, {"--add-node", "--node=x", "--upgrade"}, {"--add-node", "--node=x", "--uninstall"}, {"--uninstall", "--reinstall"}, {"--install", "--upgrade"}, {"--reinstall", "--node=x"}, {"--dry-run", "--check"}, {"--node=x", "--central-only"}} {
		if validateActions(args) == nil {
			t.Fatal("accepted conflicting flags", args)
		}
	}
	for _, args := range [][]string{{"--add-node", "--node=x"}, {"--add-node", "--node=x", "--resume"}, {"--add-node", "--node=x", "--rollback"}, {"--dry-run", "--uninstall"}, {"--dry-run", "--reinstall"}, {"--install", "--non-interactive"}, {"--uninstall", "--node=x"}, {"--uninstall", "--central-only"}} {
		if err := validateActions(args); err != nil {
			t.Fatal(args, err)
		}
	}
}

func TestUninstallMenuScopesAndBackNavigation(t *testing.T) {
	load := func() ([]common.Map, error) {
		return []common.Map{
			{"id": "node-202", "name": "子服务器202", "host": "154.89.148.202", "enabled": true},
			{"id": "node-28", "name": "子服务器28", "host": "8.134.14.28", "enabled": false},
		}, nil
	}
	for _, tc := range []struct {
		input string
		want  []string
	}{
		{"3\n1\n", []string{"--uninstall"}},
		{"3\n2\n", []string{"--uninstall", "--central-only"}},
		{"3\n3\n1\n", []string{"--uninstall", "--node", "node-202"}},
		{"3\n3\n2\n", []string{"--uninstall", "--node", "node-28"}},
		{"3\n0\n1\n", []string{"--install"}},
		{"3\n3\n0\n2\n", []string{"--uninstall", "--central-only"}},
		{"3\n3\n0\n0\n2\n", []string{"--reinstall"}},
		{"3\nbad\n3\n9\n-1\nbad\n2\n", []string{"--uninstall", "--node", "node-28"}},
	} {
		var out bytes.Buffer
		got, err := selectActionWithNodes(nil, strings.NewReader(tc.input), &out, load)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("input=%q got=%v err=%v", tc.input, got, err)
		}
		if strings.Contains(tc.input, "3\n3\n") && !strings.Contains(out.String(), "8.134.14.28") {
			t.Fatal("disabled node omitted")
		}
	}
	if _, err := selectActionWithNodes(nil, strings.NewReader("3\n0\n0\n"), new(bytes.Buffer), load); !errors.Is(err, errMenuExit) {
		t.Fatal(err)
	}
	if _, err := selectActionWithNodes(nil, strings.NewReader("3\n3\n"), new(bytes.Buffer), load); err == nil {
		t.Fatal("EOF selected node")
	}
}

func TestUninstallStrictArgumentsRejectTyposBeforeScopeSelection(t *testing.T) {
	for _, args := range [][]string{
		{"--uninstall", "--centrl-only"},
		{"--uninstall", "--nod", "node-28"},
		{"--uninstall", "--node"},
		{"--uninstall", "--node", "--non-interactive"},
		{"--uninstall", "--node="},
		{"--uninstall", "--uninstall=maybe"},
		{"--uninstall", "--yara-rules", "fixture.yar"},
	} {
		if err := validateActions(args); err == nil {
			t.Fatal("unsafe arguments accepted", args)
		}
	}
	parsed, err := parseBootstrapArgs([]string{"--uninstall=true", "--node=node-28", "--non-interactive"})
	if err != nil || parsed["--uninstall"] != "true" || parsed["--node"] != "node-28" {
		t.Fatal(parsed, err)
	}
}

func TestAdditionMenuScopeAndNavigation(t *testing.T) {
	load := func() ([]common.Map, error) {
		return []common.Map{
			{"id": "disabled", "name": "停用节点", "host": "192.0.2.1", "enabled": false},
			{"id": "node-202", "name": "子服务器202", "host": "154.89.148.202", "enabled": true},
			{"id": "node-28", "name": "子服务器28", "host": "8.134.14.28", "enabled": true},
		}, nil
	}
	for _, tc := range []struct {
		input string
		args  []string
		want  []string
	}{
		{"4\n1\n", nil, []string{"--add-node", "--node", "node-202"}},
		{"4\n9\n-1\nbad\n 2 \n", nil, []string{"--add-node", "--node", "node-28"}},
		{"4\n0\n1\n", nil, []string{"--install"}},
		{"4\n0\n4\n2\n", nil, []string{"--add-node", "--node", "node-28"}},
		{"4\n2\n", []string{"--config", "custom.yaml", "--central-only=true"}, []string{"--config", "custom.yaml", "--add-node", "--node", "node-28"}},
		{"4\n1\n", []string{"--node=old"}, []string{"--add-node", "--node", "node-202"}},
	} {
		var out bytes.Buffer
		got, err := selectActionWithNodes(tc.args, strings.NewReader(tc.input), &out, load)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("input=%q got=%v err=%v", tc.input, got, err)
		}
		if err := validateActions(got); err != nil {
			t.Fatal("menu generated conflicting scope", got, err)
		}
		if !strings.Contains(out.String(), "4、增加子服务器") || strings.Contains(out.String(), "192.0.2.1") {
			t.Fatal("menu missing addition or displaying disabled node")
		}
	}
	if _, err := selectActionWithNodes(nil, strings.NewReader("4\n0\n0\n"), new(bytes.Buffer), load); !errors.Is(err, errMenuExit) {
		t.Fatal(err)
	}
	if _, err := selectActionWithNodes(nil, strings.NewReader("4\n"), new(bytes.Buffer), load); err == nil {
		t.Fatal("EOF must not add a node")
	}
	empty := func() ([]common.Map, error) {
		return []common.Map{{"id": "disabled", "enabled": false}}, nil
	}
	var out bytes.Buffer
	if _, err := selectActionWithNodes(nil, strings.NewReader("4\n0\n"), &out, empty); !errors.Is(err, errMenuExit) || !strings.Contains(out.String(), "没有启用的子服务器") {
		t.Fatal("no enabled nodes must return to main menu", err, out.String())
	}
	loadErr := errors.New("invalid_configuration")
	if _, err := selectActionWithNodes(nil, strings.NewReader("4\n1\n"), new(bytes.Buffer), func() ([]common.Map, error) { return nil, loadErr }); !errors.Is(err, loadErr) {
		t.Fatal("configuration errors must stop before deployment", err)
	}
}
