package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	// Specify the path to your binary
	binaryPath := "../target/release/casper_vault_plugin"

	// Start the binary as a separate process
	cmd := exec.Command(binaryPath)

	// Capture stdout
	cmd.Stdout = os.Stdout

	err := cmd.Start()
	if err != nil {
		fmt.Println("Failed to start Rust binary:", err)
		os.Exit(1)
	}

	err = plugin.Serve(&plugin.ServeOpts{
		TLSProviderFunc: tlsProviderFunc,
	})
	if err != nil {
		fmt.Println("Failed to serve Vault plugin:", err)
		os.Exit(1)
	}
}
