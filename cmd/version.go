package cmd

import (
	"fmt"
	"github.com/scribd/keymaster/pkg/keymaster"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print keymaster version",
	Long: `
Print keymaster version and exit.
`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("%s\n", keymaster.VERSION)
	},
}
