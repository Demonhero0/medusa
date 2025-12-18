package dataflow

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

type StorageSlot struct {
	Address common.Address // contract address
	Slot    *uint256.Int
}

func (s *StorageSlot) String() string {
	var sb strings.Builder

	sb.WriteString(s.Address.Hex())
	sb.WriteString(":")
	sb.WriteString(s.Slot.Hex())

	return sb.String()
}

type Dataflow struct {
	Write    *ProgramPosition
	Read     *ProgramPosition
	Variable *StorageSlot
}

func (df *Dataflow) String() string {
	var sb strings.Builder

	sb.WriteString(df.Write.String())
	sb.WriteString("-")
	sb.WriteString(df.Variable.String())
	sb.WriteString("-")
	sb.WriteString(df.Read.String())

	return sb.String()
}
