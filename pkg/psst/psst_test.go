package psst

import (
	"fmt"
	"git.lo/ops/vaulttest/pkg/vaulttest"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

var tmpDir string
var testServer *vaulttest.VaultDevServer

func TestMain(m *testing.M) {
	setUp()

	code := m.Run()

	tearDown()

	os.Exit(code)
}

func setUp() {
	dir, err := ioutil.TempDir("", "psst")
	if err != nil {
		fmt.Printf("Error creating temp dir %q: %s\n", tmpDir, err)
		os.Exit(1)
	}

	tmpDir = dir

	testServer = vaulttest.NewVaultDevServer("")

	if !testServer.Running {
		testServer.ServerStart()
	}

}

func tearDown() {
	if _, err := os.Stat(tmpDir); !os.IsNotExist(err) {
		os.Remove(tmpDir)
	}

	testServer.ServerShutDown()

}

func TestVaultTestClient(t *testing.T) {
	assert.True(t, 1 == 1, "the law of identity has been broken")

	client := testServer.VaultTestClient()

	secret, err := client.Logical().Read("secret/config")
	if err != nil {
		log.Printf("Failed to default secret config: %s", err)
		t.Fail()
	}

	assert.True(t, secret != nil, "We got a secret from the test vault server")
}
