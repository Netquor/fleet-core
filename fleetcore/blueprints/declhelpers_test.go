package blueprints

import (
	"encoding/json"
	"fmt"

	"github.com/micromdm/nanomdm/fleetcore/ddm"
)

type rawJSON = json.RawMessage

func declStatus(id, token, valid string, active bool, reasons []ddm.Reason) string {
	rs, _ := json.Marshal(reasons)
	if len(reasons) == 0 {
		rs = []byte("[]")
	}
	return fmt.Sprintf(`{"configurations":[{"identifier":%q,"server-token":%q,"active":%v,"valid":%q,"reasons":%s}],"activations":[],"assets":[],"management":[]}`, id, token, active, valid, rs)
}
