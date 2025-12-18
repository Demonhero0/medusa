package branchdistance

import (
	"fmt"
	"strings"

	"github.com/crytic/medusa-geth/core/vm"
)

type BranchMap struct {
	BranchIds map[uint64]int // pc -> false branch id, true branch id = false branch id + 1
}

func (bm *BranchMap) Size() int {
	return len(bm.BranchIds) * 2
}

func (bm *BranchMap) GetBranchId(pc uint64, cond bool) int {
	branchId := bm.BranchIds[pc]
	if cond {
		branchId += 1
	}
	return branchId
}

func GetBranchMapFromBytecode(bytecode []byte) *BranchMap {
	branchIds := make(map[uint64]int)
	id := 0

	it := NewInstructionIterator(bytecode)

	for it.Next() {
		if it.Op() == vm.JUMPI {
			branchIds[it.PC()] = id
			id += 2
		}
	}
	if err := it.Error(); err != nil {
		// Ignore incomplete push instruction errors
		if !strings.HasPrefix(err.Error(), "incomplete push instruction") {
			return nil
		}
	}

	return &BranchMap{
		BranchIds: branchIds,
	}
}

// Iterator for disassembled EVM instructions
type instructionIterator struct {
	code    []byte
	pc      uint64
	arg     []byte
	op      vm.OpCode
	error   error
	started bool
}

// NewInstructionIterator create a new instruction iterator.
func NewInstructionIterator(code []byte) *instructionIterator {
	it := new(instructionIterator)
	it.code = code
	return it
}

// Next returns true if there is a next instruction and moves on.
func (it *instructionIterator) Next() bool {
	if it.error != nil || uint64(len(it.code)) <= it.pc {
		// We previously reached an error or the end.
		return false
	}

	if it.started {
		// Since the iteration has been already started we move to the next instruction.
		if it.arg != nil {
			it.pc += uint64(len(it.arg))
		}
		it.pc++
	} else {
		// We start the iteration from the first instruction.
		it.started = true
	}

	if uint64(len(it.code)) <= it.pc {
		// We reached the end.
		return false
	}

	it.op = vm.OpCode(it.code[it.pc])
	if it.op.IsPush() {
		a := uint64(it.op) - uint64(vm.PUSH1) + 1
		u := it.pc + 1 + a
		if uint64(len(it.code)) <= it.pc || uint64(len(it.code)) < u {
			it.error = fmt.Errorf("incomplete push instruction at %v", it.pc)
			return false
		}
		it.arg = it.code[it.pc+1 : u]
	} else {
		it.arg = nil
	}
	return true
}

// Error returns any error that may have been encountered.
func (it *instructionIterator) Error() error {
	return it.error
}

// PC returns the PC of the current instruction.
func (it *instructionIterator) PC() uint64 {
	return it.pc
}

// Op returns the opcode of the current instruction.
func (it *instructionIterator) Op() vm.OpCode {
	return it.op
}

// Arg returns the argument of the current instruction.
func (it *instructionIterator) Arg() []byte {
	return it.arg
}
