package cmd

import (
	"github.com/scribd/keymaster/pkg/keymaster"
	"github.com/scribd/vaultlibs/pkg/vaultlibs"
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

		data, err := keymaster.LoadSecretYamls(args, verbose)
		if err != nil {
			log.Fatalf("failed to load secret definitions: %s", err)
		}

		vaultlibs.VAULT_SITE_CONFIG = vaultlibs.VaultSiteConfig{
			Address: "https://vault.corp.scribd.com",
			CACertificate: `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
`,
		}

		client, err := vaultlibs.VaultAuth("", "", !noninteractive, verbose)
		if err != nil {
			log.Fatalf("Failed to create Vault client: %s", err)
		}

		km := keymaster.NewKeyMaster(client)

		for _, config := range data {
			team, err := km.NewTeam(config, verbose)
			if err != nil {
				log.Fatalf("Failed to load secret definitions: %s", err)
			} else {
				err = km.ConfigureTeam(team, verbose)
				if err != nil {
					log.Fatalf("Failed to configure vault for secret definitions: %s", err)
				}
			}
		}
	},
}
