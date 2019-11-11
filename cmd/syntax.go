package cmd

import (
	"fmt"
	"github.com/scribd/keymaster/pkg/keymaster"
	"github.com/spf13/cobra"
	"log"
)

func init() {
	rootCmd.AddCommand(syntaxCmd)
}

var syntaxCmd = &cobra.Command{
	Use:   "syntax",
	Short: "Check syntax of secret yamls",
	Long: `
Check syntax of secret yamls.
`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 && configPath == "" {
			log.Fatal("No config files or directories provided.  Cannot continue.  Try again with `dbt keymaster sync -f <file>` or `dbt keymaster sync <file1> <file2> ...`")
		}

		if configPath != "" {
			args = append(args, configPath)
		}

		_, err := keymaster.LoadSecretYamls(args, verbose)
		if err != nil {
			log.Fatalf("failed to load secret definitions: %s", err)
		}

		fmt.Printf("Data loaded successfully.\n\n")
	},
}
