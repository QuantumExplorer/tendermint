package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	tmjson "github.com/quantumexplorer/tendermint/libs/json"
	"github.com/quantumexplorer/tendermint/p2p/upnp"
)

// ProbeUpnpCmd adds capabilities to test the UPnP functionality.
var ProbeUpnpCmd = &cobra.Command{
	Use:   "probe_upnp",
	Short: "Test UPnP functionality",
	RunE:  probeUpnp,
}

func probeUpnp(cmd *cobra.Command, args []string) error {
	capabilities, err := upnp.Probe(logger)
	if err != nil {
		fmt.Println("Probe failed: ", err)
	} else {
		fmt.Println("Probe success!")
		jsonBytes, err := tmjson.Marshal(capabilities)
		if err != nil {
			return err
		}
		fmt.Println(string(jsonBytes))
	}
	return nil
}
