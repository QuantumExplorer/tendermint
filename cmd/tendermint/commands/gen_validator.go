package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	tmjson "github.com/quantumexplorer/tendermint/libs/json"
	"github.com/quantumexplorer/tendermint/privval"
)

// GenValidatorCmd allows the generation of a keypair for a
// validator.
var GenValidatorCmd = &cobra.Command{
	Use:   "gen_validator",
	Short: "Generate new validator keypair",
	Run:   genValidator,
}

func genValidator(cmd *cobra.Command, args []string) {
	pv := privval.GenFilePV("", "")
	jsbz, err := tmjson.Marshal(pv)
	if err != nil {
		panic(err)
	}
	fmt.Printf(`%v
`, string(jsbz))
}
