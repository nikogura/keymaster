package cmd

import (
	"git.lo/dbt/keymaster/pkg/keymaster"
	"git.lo/ops/scrutil/pkg/scrutil"
	"github.com/spf13/cobra"
	"log"
)

var configPath string

func init() {
	rootCmd.AddCommand(syncCmd)
	syncCmd.Flags().StringVarP(&configPath, "config", "c", "", "Secret config file or directory containing config yaml's.")
}

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Syncs Secret config yamls with Vault",
	Long: `
Syncs Secret config yamls with Vault.
`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 && configPath == "" {
			log.Fatal("No config files or directories provided.  Cannot continue.  Try again with `dbt keymaster sync -f <file>` or `dbt keymaster sync <file1> <file2> ...`")
		}

		if configPath != "" {
			args = append(args, configPath)
		}

		data, err := keymaster.LoadSecretYamls(args)
		if err != nil {
			log.Fatalf("failed to load secret definitions: %s", err)
		}

		// scrutil doesn't take the env var, this is how you override the default
		scrutil.VAULT_ADDR = vaultAddress

		client, err := scrutil.GetVaultClient(!noninteractive, verbose)
		if err != nil {
			log.Fatalf("Failed to create Vault client: %s", err)
		}

		km := keymaster.NewKeyMaster(client)

		for _, config := range data {
			ns, err := km.NewNamespace(config)
			if err != nil {
				log.Fatalf("Failed to load secret definitions: %s", err)
			} else {
				err = km.ConfigureNamespace(ns)
				if err != nil {
					log.Fatalf("Failed to configure vault for secret definitions: %s", err)
				}
			}
		}
	},
}
