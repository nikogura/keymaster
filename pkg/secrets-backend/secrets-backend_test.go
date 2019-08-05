package secrets_backend

import (
	"fmt"
	"git.lo/ops/vaulttest/pkg/vaulttest"
	"io/ioutil"
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

	//port, err := freeport.GetFreePort()
	//if err != nil {
	//	log.Fatalf("Failed to get a free port on which to run the test vault server: %s", err)
	//}
	//
	//testAddress := fmt.Sprintf("127.0.0.1:%d", port)
	//
	//testServer = vaulttest.NewVaultDevServer(testAddress)
	//
	//if !testServer.Running {
	//	testServer.ServerStart()
	//}

}

func tearDown() {
	if _, err := os.Stat(tmpDir); !os.IsNotExist(err) {
		os.Remove(tmpDir)
	}

	//testServer.ServerShutDown()

}

//func TestVaultTestClient(t *testing.T) {
//	assert.True(t, 1 == 1, "the law of identity has been broken")
//
//	client := testServer.VaultTestClient()
//
//	secret, err := client.Logical().Read("secret/config")
//	if err != nil {
//		log.Printf("Failed to default secret config: %s", err)
//		t.Fail()
//	}
//
//	assert.True(t, secret != nil, "We got a secret from the test vault server")
//}
