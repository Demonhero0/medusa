package storagewrite

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
	Value   *uint256.Int // value at the slot, if applicable
}

func (s *StorageSlot) String() string {
	var sb strings.Builder

	sb.WriteString(s.Address.Hex())
	sb.WriteString(":")
	sb.WriteString(s.Slot.Hex())

	return sb.String()
}

type StorageWrite struct {
	Position *ProgramPosition
	Variable *StorageSlot
}

func (s *StorageWrite) String() string {
	var sb strings.Builder

	sb.WriteString(s.Position.String())
	sb.WriteString("-")
	sb.WriteString(s.Variable.String())

	return sb.String()
}

var (
	slice0 = uint256.NewInt(uint64(1)).Lsh(uint256.NewInt(uint64(1)), 4)  // 2^4
	slice1 = uint256.NewInt(uint64(1)).Lsh(uint256.NewInt(uint64(1)), 16) // 2^16
	slice2 = uint256.NewInt(uint64(1)).Lsh(uint256.NewInt(uint64(1)), 64) // 2^64
)

// mapping a value to a abstract bucket string
func bucket(value *uint256.Int) string {
	if value.Cmp(slice0) < 0 {
		return "0-2^4"
	} else if value.Cmp(slice1) < 0 {
		return "2^4-2^16"
	} else if value.Cmp(slice2) < 0 {
		return "2^16-2^64"
	} else {
		return "2^64-2^256"
	}
}

func (s *StorageWrite) Bucket() string {
	var sb strings.Builder

	sb.WriteString(s.Position.String())
	sb.WriteString("-")
	sb.WriteString(s.Variable.String())

	sb.WriteString("-")
	sb.WriteString(bucket(s.Variable.Value))

	return sb.String()
}
