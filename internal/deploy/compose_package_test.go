package deploy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"webscan/internal/common"
)

func TestComposePackagesKeepIdentitiesAndSecretsSeparated(t *testing.T) {
	c := fixture(t)
	common.M(c.Raw["registry"])["prefix"] = "docker.io/gzdzh"
	common.M(c.Raw["registry"])["username"] = "publisher-must-not-export"
	common.M(c.Raw["registry"])["password"] = "registry-must-not-export"
	for _, n := range c.Nodes {
		common.M(n["ssh"])["password"] = "ssh-must-not-export"
	}
	before := string(common.JSON(c.Raw))
	dir := filepath.Join(t.TempDir(), "packages")
	launcher := []byte("include:\n  - path: ${WEBSCAN_COMPOSE_FILE:-./compose-deploy/central/services.yaml}\n")
	if err := PrepareCompose(c, dir, launcher); err != nil {
		t.Fatal(err)
	}
	if string(common.JSON(c.Raw)) != before {
		t.Fatal("generator changed input configuration")
	}
	central, err := common.ReadJSON(filepath.Join(dir, "central/config/runtime.json"))
	if err != nil {
		t.Fatal(err)
	}
	var previousToken string
	for _, n := range c.Selected("") {
		id := common.S(n["id"])
		runtime, err := common.ReadJSON(filepath.Join(dir, id, "config/runtime.json"))
		if err != nil {
			t.Fatal(err)
		}
		token := common.S(runtime["token"])
		if token == "" || token == previousToken || token != common.S(common.M(common.M(central["nodes"])[id])["token"]) {
			t.Fatal("node identity mismatch")
		}
		previousToken = token
		caPEM, _ := os.ReadFile(filepath.Join(dir, id, "config/pki/ca.crt"))
		caBlock, _ := pem.Decode(caPEM)
		if caBlock == nil {
			t.Fatal("missing CA")
		}
		ca, err := x509.ParseCertificate(caBlock.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		pair, err := tls.LoadX509KeyPair(filepath.Join(dir, id, "config/pki/server.crt"), filepath.Join(dir, id, "config/pki/server.key"))
		if err != nil {
			t.Fatal(err)
		}
		cert, _ := x509.ParseCertificate(pair.Certificate[0])
		if cert.VerifyHostname(common.S(n["host"])) != nil || cert.CheckSignatureFrom(ca) != nil {
			t.Fatal("metrics certificate mismatch")
		}
		for _, name := range []string{"data/textfile", "logs", "probe", "vector-data"} {
			if info, err := os.Stat(filepath.Join(dir, id, name)); err != nil || !info.IsDir() {
				t.Fatal("missing writable directory")
			}
		}
		b, _ := os.ReadFile(filepath.Join(dir, id, "services.yaml"))
		var compose common.Map
		if err := yaml.Unmarshal(b, &compose); err != nil {
			t.Fatal(err)
		}
		if len(common.M(compose["services"])) != 3 {
			t.Fatal("missing node transport or exporter")
		}
	}
	err = filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), "must-not-export") {
			t.Fatal("registry credentials exported")
		}
		if entry.Name() == "ca.key" && path != filepath.Join(dir, "private/ca.key") {
			t.Fatal("CA signer exported to host")
		}
		if entry.Name() == "services.yaml" {
			var compose common.Map
			if err := yaml.Unmarshal(b, &compose); err != nil {
				return err
			}
			for _, v := range common.M(compose["services"]) {
				service := common.M(v)
				if !strings.HasPrefix(common.S(service["image"]), "docker.io/") {
					t.Fatal("non-DockerHub image")
				}
				for _, v := range common.A(service["volumes"]) {
					mount := common.M(v)
					if common.B(common.M(mount["bind"])["create_host_path"]) {
						t.Fatal("missing config silently creates directory")
					}
					source := common.S(mount["source"])
					if strings.HasPrefix(source, "./") {
						if _, err := os.Stat(filepath.Join(filepath.Dir(path), source)); err != nil {
							t.Fatal("package bind source missing", source)
						}
					}
				}
			}
		}
		if info, _ := entry.Info(); info.Mode().Perm() != 0600 {
			t.Fatal("insecure package file mode")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := PrepareCompose(c, dir, launcher); err == nil {
		t.Fatal("existing credentials overwritten")
	}
}

func TestComposePackagesRejectUnsupportedModesBeforeWriting(t *testing.T) {
	for _, mode := range []string{"private", "other-registry", "reuse", "reserved-node"} {
		t.Run(mode, func(t *testing.T) {
			c := fixture(t)
			common.M(c.Raw["registry"])["prefix"] = "docker.io/gzdzh"
			switch mode {
			case "private":
				common.M(c.Raw["registry"])["auth_required"] = true
			case "other-registry":
				common.M(c.Raw["registry"])["prefix"] = "registry.example.com/team"
			case "reuse":
				common.M(common.M(c.Raw["central"])["reuse_existing"])["grafana"] = true
			case "reserved-node":
				oldID := common.S(c.Nodes[0]["id"])
				c.Nodes[0]["id"] = "central"
				order := common.SS(common.M(c.Raw["deployment"])["node_order"])
				for i, id := range order {
					if id == oldID {
						order[i] = "central"
					}
				}
				common.M(c.Raw["deployment"])["node_order"] = order
			}
			dir := filepath.Join(t.TempDir(), "packages")
			if err := PrepareCompose(c, dir, []byte("include: []")); err == nil {
				t.Fatal("unsupported mode accepted")
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatal("unsupported mode created output")
			}
		})
	}
}
