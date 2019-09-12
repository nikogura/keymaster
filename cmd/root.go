// Copyright © 2019 Nik Ogura <nik@scribd.com>
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

var verbose bool
var noninteractive bool
var vaultAddress string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "keymaster",
	Short: "Secrets Management Tool",
	// Note:  Change the following line to backticks for long multiline descriptions.
	Long: "Secrets Management Tool",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output.")
	rootCmd.PersistentFlags().BoolVarP(&noninteractive, "noninteractive", "n", false, "Noninteractive use. Do not prompt for credentials.")
	rootCmd.PersistentFlags().StringVarP(&vaultAddress, "address", "a", "https://vault-prod.inf.scribd.com:8200", "Vault address.")
}
