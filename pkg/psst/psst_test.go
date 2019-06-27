package psst

import (
	"bufio"
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/go-homedir"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

var tmpDir string
var testServer *exec.Cmd
var testServerRunning bool
var testUnsealKey string
var testRootToken string
var userToken string
var userTokenFile string

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

	// find the user's vault token file if it exists
	homeDir, err := homedir.Dir()
	if err != nil {
		log.Fatalf("Unable to determine user's home dir: %s", err)
	}

	userTokenFile = fmt.Sprintf("%s/.vault-token", homeDir)

	// read it into memory cos the test server is gonna overwrite it
	if _, err := os.Stat(userTokenFile); !os.IsNotExist(err) {
		tokenBytes, err := ioutil.ReadFile(userTokenFile)
		if err == nil {
			userToken = string(tokenBytes)
		}
	}

	// only start if we're not already running (all tests will run this setUp function
	if !testServerRunning {
		vault, err := exec.LookPath("vault")
		if err != nil {
			log.Fatal("'vault' is not installed and available on the path")
		}

		testServer = exec.Command(vault, "server", "-dev")

		testServer.Stderr = os.Stderr
		out, err := testServer.StdoutPipe()
		if err != nil {
			log.Fatalf("unable to connect to testserver's stdout: %s", err)
		}

		err = testServer.Start()

		scanner := bufio.NewScanner(out)

		unsealPattern := regexp.MustCompile(`^Unseal Key:.+`)
		rootTokenPattern := regexp.MustCompile(`^Root Token:.+`)

		for testUnsealKey == "" || testRootToken == "" {
			scanner.Scan()
			line := scanner.Text()

			if testUnsealKey == "" && unsealPattern.MatchString(line) {
				parts := strings.Split(line, ": ")
				if len(parts) > 1 {
					testUnsealKey = parts[1]
					strings.TrimRight(testUnsealKey, "\n")
					strings.TrimLeft(testUnsealKey, " ")
				}

				continue
			}

			if testRootToken == "" && rootTokenPattern.MatchString(line) {
				parts := strings.Split(line, ": ")
				if len(parts) > 1 {
					testRootToken = parts[1]
					strings.TrimRight(testUnsealKey, "\n")
					strings.TrimLeft(testUnsealKey, " ")
				}

				continue
			}

		}

		// wait a bit for things to be ready.
		//fmt.Printf("Waiting 3 seconds for the test server to spool up.\n")
		//time.Sleep(3 * time.Second)

		testServerRunning = true

	}
}

func tearDown() {
	if testServerRunning {
		testServer.Process.Kill()
	}

	if _, err := os.Stat(tmpDir); !os.IsNotExist(err) {
		os.Remove(tmpDir)
	}

	// restore the user's vault token when we're done.
	if userToken != "" {
		_ = ioutil.WriteFile(userTokenFile, []byte(userToken), 0600)
	}
}

// VaultTestClient returns a configured vault client for the test vault server.  By default the client returned has the root token for the test vault instance set.  If you want something else, you will need to reconfigure it.
func VaultTestClient() *api.Client {
	config := api.DefaultConfig()

	err := config.ReadEnvironment()
	if err != nil {
		log.Fatalf("failed to inject environment into test vault client config")
	}

	config.Address = "http://127.0.0.1:8200"

	client, err := api.NewClient(config)
	if err != nil {
		log.Fatalf("failed to create test vault api client: %s", err)
	}

	client.SetToken(testRootToken)

	return client

}

func TestVaultTestClient(t *testing.T) {
	assert.True(t, 1 == 1, "the law of identity has been broken")

	client := VaultTestClient()

	secret, err := client.Logical().Read("secret/config")
	if err != nil {
		log.Printf("Failed to default secret config: %s", err)
		t.Fail()
	}

	assert.True(t, secret != nil, "We got a secret from the test vault server")
}
