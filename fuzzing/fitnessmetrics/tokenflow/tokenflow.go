package tokenflow

import (
	"strconv"
	"strings"

	"github.com/crytic/medusa-geth/common"
	"github.com/holiman/uint256"
)

type ProgramPosition struct {
	Address common.Address // code address
	Create  bool           // whether Pc is in the init bytecode
	Pc      uint64
}

func (s *ProgramPosition) String() string {
	var sb strings.Builder

	sb.WriteString(s.Address.Hex())
	if s.Create {
		sb.WriteString("c")
	}
	sb.WriteString(":")
	sb.WriteString(strconv.FormatUint(s.Pc, 16))

	return sb.String()
}

type Flow struct {
	From   common.Address // from address
	To     common.Address // to address
	Amount *uint256.Int   // amount transferred
	Token  common.Address // token address
}

type Tokenflow struct {
	Position *ProgramPosition // position in the code
	Flow     *Flow            // flow of the token transfer
}

func (df *Tokenflow) String() string {
	var sb strings.Builder

	sb.WriteString(df.Position.String())

	return sb.String()
}
