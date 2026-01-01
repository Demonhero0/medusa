package bugdetector

import (
	"fmt"

	"github.com/crytic/medusa-geth/common"
	"github.com/crytic/medusa-geth/core/tracing"
	"github.com/crytic/medusa-geth/core/vm"
)

type TaintOpcode struct {
	opcode byte
	pc     uint64
}

type TaintMemory struct {
	opcode byte
	pc     uint64
	start  uint64
	end    uint64
}

type TaintStorageSlot struct {
	opcode byte
	pc     uint64
	slot   common.Hash
	value  common.Hash
}

func (t *TaintStorageSlot) id() string {
	if t.pc == 0 {
		return fmt.Sprintf("%s", vm.OpCode(t.opcode).String())
	} else {
		return fmt.Sprintf("%d-%s", t.pc, vm.OpCode(t.opcode).String())
	}
}

func (t *TaintOpcode) id() string {
	if t.pc == 0 {
		return fmt.Sprintf("%s", vm.OpCode(t.opcode).String())
	} else {
		return fmt.Sprintf("%d-%s", t.pc, vm.OpCode(t.opcode).String())
	}
}

func (t *TaintMemory) id() string {
	if t.pc == 0 {
		return fmt.Sprintf("%s", vm.OpCode(t.opcode).String())
	} else {
		return fmt.Sprintf("%d-%s", t.pc, vm.OpCode(t.opcode).String())
	}
}

type TaintOpcodes map[string]*TaintOpcode

// TaintAnalyzer performs taint analysis on stack during EVM execution.
type TaintAnalyzer struct {
	// map from stack index to TaintOpcodes, which is a map from taint ID (pc-opcode) to TaintOpcode
	taintStacks map[int]TaintOpcodes
	// map from taint ID to TaintMemory
	taintMemory map[string]TaintMemory
	// map from storage slot to TaintOpcodes, which is a map from taint ID (pc-opcode) to TaintOpcode
	taintStorage map[common.Hash]TaintOpcodes
}

func NewTaintAnalyzer() *TaintAnalyzer {
	return &TaintAnalyzer{
		taintStacks:  make(map[int]TaintOpcodes),
		taintMemory:  make(map[string]TaintMemory),
		taintStorage: make(map[common.Hash]TaintOpcodes),
	}
}

func (ta *TaintAnalyzer) AddTaintSourceByOpcode(opcode byte) {
	taint := &TaintOpcode{
		opcode: opcode,
		pc:     0, // pc is not relevant for this use case
	}

	if _, exists := ta.taintStacks[0]; !exists {
		ta.taintStacks[0] = make(TaintOpcodes)
	}
	ta.taintStacks[0][taint.id()] = taint
}

func (ta *TaintAnalyzer) AddTaintSource(opcode byte, pc uint64) {
	taint := &TaintOpcode{
		opcode: opcode,
		pc:     pc,
	}

	if _, exists := ta.taintStacks[0]; !exists {
		ta.taintStacks[0] = make(TaintOpcodes)
	}
	ta.taintStacks[0][taint.id()] = taint
}

func (ta *TaintAnalyzer) AddTaintSourceByString(id string) {
	if _, exists := ta.taintStacks[0]; !exists {
		ta.taintStacks[0] = make(TaintOpcodes)
	}
	ta.taintStacks[0][id] = &TaintOpcode{
		opcode: 0x0,
		pc:     0,
	}
}

// add taint memory region with pc-opcode identifier
func (ta *TaintAnalyzer) AddTaintSourceMemory(start, end uint64, opcode byte, pc uint64) {
	taint := TaintMemory{
		opcode: opcode,
		pc:     pc,
		start:  start,
		end:    end,
	}
	ta.taintMemory[taint.id()] = taint
}

// add taint memory region with opcode identifier only
func (ta *TaintAnalyzer) AddTaintSourceMemoryByOpcode(opcode byte, start, end uint64) {
	taint := TaintMemory{
		opcode: opcode,
		pc:     0,
		start:  start,
		end:    end,
	}
	ta.taintMemory[taint.id()] = taint
}

func (ta *TaintAnalyzer) PropagateTaint(opcode byte, scope tracing.OpContext) {
	if len(ta.taintStacks) == 0 {
		return
	}
	op := vm.OpCode(opcode)

	if op.IsPush() || op == vm.PUSH0 {
		ta.shiftDown()
		return
	}

	scopeContext := scope.(*vm.ScopeContext)

	// fmt.Printf("[TAINT] TaintStacks before %s PropagateTaint: %v\n", vm.OpCode(opcode), ta.taintStacks)
	switch op {
	// Opcodes that push a value without consuming stack items that could be tainted sources.
	// We treat the pushed value as untainted. The external tracer can add taint if needed.
	case vm.ADDRESS, vm.ORIGIN, vm.CALLER, vm.CALLVALUE, vm.CALLDATASIZE, vm.CODESIZE, vm.GASPRICE,
		vm.COINBASE, vm.TIMESTAMP, vm.NUMBER, vm.DIFFICULTY, vm.GASLIMIT, vm.BLOCKHASH, vm.MSIZE,
		vm.PC, vm.GAS, vm.RETURNDATASIZE, vm.CHAINID, vm.SELFBALANCE, vm.BASEFEE:
		ta.shiftDown()

	// --- (1 pop, 1 push) ---
	// Taint of the operand is propagated to the result. The stack depth doesn't change.
	case vm.MLOAD:
		// deal with memory propagate
		offset := scopeContext.Stack.Back(0).Uint64()
		size := uint64(32)
		ta.memoryToStack(offset, offset+size)

	case vm.SLOAD:
		// key := common.BigToHash(scopeContext.Stack.Back(0).ToBig())
		// ta.storageToStack(key)

	case vm.ISZERO, vm.NOT, vm.BYTE, vm.BALANCE, vm.EXTCODESIZE, vm.EXTCODEHASH, vm.CALLDATALOAD:

	// --- (2 pops, 1 push) ---
	case vm.ADD, vm.SUB, vm.MUL, vm.DIV, vm.SDIV, vm.MOD, vm.SMOD, vm.EXP,
		vm.SIGNEXTEND, vm.LT, vm.GT, vm.SLT, vm.SGT, vm.EQ, vm.AND, vm.OR,
		vm.XOR, vm.SHL, vm.SHR, vm.SAR, vm.KECCAK256:
		ta.mergeTaintStacks(1, 0)
		ta.shiftUp()

	// --- (3 pops, 1 push) ---
	case vm.ADDMOD, vm.MULMOD:
		ta.mergeTaintStacks(2, 0)
		ta.mergeTaintStacks(2, 1)
		ta.shiftUp()
		ta.shiftUp()

	// --- (1 pop, 0 push) ---
	case vm.POP, vm.JUMP:
		ta.shiftUp()

	// --- (2 pops, 0 push) ---
	case vm.MSTORE:
		offset := scopeContext.Stack.Back(0).Uint64()
		size := uint64(32)
		ta.stackToMemory(1, offset, offset+size)

		ta.shiftUp()
		ta.shiftUp()

	case vm.MSTORE8:
		offset := scopeContext.Stack.Back(0).Uint64()
		size := uint64(1)
		ta.stackToMemory(1, offset, offset+size)

		ta.shiftUp()
		ta.shiftUp()

	case vm.SSTORE:
		// key := common.BigToHash(scopeContext.Stack.Back(0).ToBig())
		// ta.stackToStorage(1, key)
		ta.shiftUp()
		ta.shiftUp()
	case vm.JUMPI, vm.RETURN, vm.REVERT:
		ta.shiftUp()
		ta.shiftUp()

	// --- (3 pops, 0 push) ---
	case vm.CODECOPY, vm.CALLDATACOPY, vm.RETURNDATACOPY:
		ta.shiftUp()
		ta.shiftUp()
		ta.shiftUp()

	// --- (4 pops, 0 push) ---
	case vm.EXTCODECOPY:
		ta.shiftUp()
		ta.shiftUp()
		ta.shiftUp()
		ta.shiftUp()

	// --- DUPn ---
	case vm.DUP1, vm.DUP2, vm.DUP3, vm.DUP4, vm.DUP5, vm.DUP6, vm.DUP7, vm.DUP8,
		vm.DUP9, vm.DUP10, vm.DUP11, vm.DUP12, vm.DUP13, vm.DUP14, vm.DUP15, vm.DUP16:
		n := int(op - vm.DUP1 + 1)
		ta.shiftDown()
		ta.copyTaintStack(n, 0) // The original n-th item is at index n after shiftDown

	// --- SWAPn ---
	case vm.SWAP1, vm.SWAP2, vm.SWAP3, vm.SWAP4, vm.SWAP5, vm.SWAP6, vm.SWAP7, vm.SWAP8,
		vm.SWAP9, vm.SWAP10, vm.SWAP11, vm.SWAP12, vm.SWAP13, vm.SWAP14, vm.SWAP15, vm.SWAP16:
		n := int(op - vm.SWAP1 + 1)
		ta.taintStacks[0], ta.taintStacks[n] = ta.taintStacks[n], ta.taintStacks[0]
		if len(ta.taintStacks[0]) == 0 {
			delete(ta.taintStacks, 0)
		}
		if len(ta.taintStacks[n]) == 0 {
			delete(ta.taintStacks, n)
		}

	// --- LOGn ---
	case vm.LOG0, vm.LOG1, vm.LOG2, vm.LOG3, vm.LOG4:
		n := int(op - vm.LOG0)
		// pops n+2 items (2 for mem, n topics)
		for i := 0; i < n+2; i++ {
			ta.shiftUp()
		}

	// --- Calls & Create ---
	case vm.CREATE: // pops 3, pushes 1
		// ignore the cross contract taint for simplicity
		// ta.mergeTaintStacks(0, 1)
		// ta.mergeTaintStacks(0, 2)
		ta.shiftUp()
		ta.shiftUp()
		ta.shiftUp()
		ta.shiftDown()
	case vm.CREATE2: // pops 4, pushes 1
		// ignore the cross contract taint for simplicity
		// ta.mergeTaintStacks(0, 1)
		// ta.mergeTaintStacks(0, 2)
		// ta.mergeTaintStacks(0, 3)
		ta.shiftUp()
		ta.shiftUp()
		ta.shiftUp()
		ta.shiftUp()
	case vm.CALL, vm.CALLCODE: // pops 7, pushes 1
		// ignore the cross contract taint for simplicity
		// for i := 1; i < 7; i++ {
		// 	ta.mergeTaintStacks(0, i)
		// }
		for i := 0; i < 7; i++ {
			ta.shiftUp()
		}
		ta.shiftDown()
	case vm.DELEGATECALL, vm.STATICCALL: // pops 6, pushes 1
		// ignore the cross contract taint for simplicity
		// for i := 1; i < 6; i++ {
		// 	ta.mergeTaintStacks(0, i)
		// }
		for i := 0; i < 6; i++ {
			ta.shiftUp()
		}
		ta.shiftDown()

		// Other opcodes do not manipulate the stack in a way that concerns taint propagation
	default:

	}
}

// IsTaintedByOpcode checks if the item at a given stack depth is tainted by a specific source.
func (ta *TaintAnalyzer) IsTaintedByOpcode(opcode byte, stackIndex int) bool {
	taintStack, exists := ta.taintStacks[stackIndex]
	if !exists {
		return false
	}

	tainted := false
	taint := TaintOpcode{
		opcode: opcode,
		pc:     0,
	}
	id := taint.id()
	if _, exists := taintStack[id]; exists {
		tainted = true
	}

	return tainted
}

// IsTaintedBy checks if the item at a given stack depth is tainted by a specific source.
func (ta *TaintAnalyzer) IsTaintedBy(opcode byte, stackIndex int) bool {
	taintStack, exists := ta.taintStacks[stackIndex]
	if !exists {
		return false
	}

	tainted := false
	for _, taint := range taintStack {
		if taint.opcode == opcode {
			tainted = true
			break
		}
	}

	return tainted
}

func (ta *TaintAnalyzer) IsTaintedByString(id string, stackIndex int) bool {
	taintStack, exists := ta.taintStacks[stackIndex]
	if !exists {
		return false
	}

	tainted := false
	if _, exists := taintStack[id]; exists {
		tainted = true
	}

	return tainted
}

func (ta *TaintAnalyzer) IsTantedMemoryByOpcode(opcode byte, start, end uint64) bool {
	tainted := false
	for _, taintMemory := range ta.taintMemory {
		if taintMemory.opcode == opcode {
			taintStart := taintMemory.start
			taintEnd := taintMemory.end

			if end <= taintStart {
				continue
			} else if start >= taintEnd {
				continue
			} else {
				tainted = true
				break
			}
		}
	}

	return tainted
}

// shiftDown simulates a push operation on the taint stack.
// It moves all existing taint stacks one level down (increasing their index).
func (ta *TaintAnalyzer) shiftDown() {
	newTaintStacks := make(map[int]TaintOpcodes, len(ta.taintStacks)+1)
	for i, stack := range ta.taintStacks {
		newTaintStacks[i+1] = stack
	}
	ta.taintStacks = newTaintStacks
}

// shiftUp simulates a pop operation on the taint stack.
// It removes the top element and moves all other stacks one level up.
func (ta *TaintAnalyzer) shiftUp() {
	if len(ta.taintStacks) == 0 {
		return
	}
	newTaintStacks := make(map[int]TaintOpcodes)
	for i, stack := range ta.taintStacks {
		if i > 0 {
			newTaintStacks[i-1] = stack
		}
	}
	ta.taintStacks = newTaintStacks
}

func (ta *TaintAnalyzer) copyTaintStack(src, dest int) {
	srcStack, exists := ta.taintStacks[src]
	if !exists {
		delete(ta.taintStacks, dest)
		return
	}

	destStack := make(TaintOpcodes, len(srcStack))
	for id, taint := range srcStack {
		destStack[id] = taint
	}
	ta.taintStacks[dest] = destStack
}

func (ta *TaintAnalyzer) mergeTaintStacks(dest, src int) {
	srcStack, srcExists := ta.taintStacks[src]
	if !srcExists {
		return
	}

	destStack, destExists := ta.taintStacks[dest]
	if !destExists {
		ta.taintStacks[dest] = make(TaintOpcodes)
		destStack = ta.taintStacks[dest]
	}

	for id, taint := range srcStack {
		destStack[id] = taint
	}
	delete(ta.taintStacks, src)
}

func (ta *TaintAnalyzer) memoryToStack(start, end uint64) {
	for _, taintMemory := range ta.taintMemory {
		taintStart := taintMemory.start
		taintEnd := taintMemory.end

		if end <= taintStart {
			continue
		} else if start >= taintEnd {
			continue
		} else {
			// taint memory goes to stack
			ta.AddTaintSource(taintMemory.opcode, taintMemory.pc)
		}
	}
}

func (ta *TaintAnalyzer) stackToMemory(stackIndex int, start, end uint64) {
	taintStack, exists := ta.taintStacks[stackIndex]
	if !exists {
		return
	}
	for id, taintOpcode := range taintStack {
		ta.taintMemory[id] = TaintMemory{
			opcode: taintOpcode.opcode,
			pc:     taintOpcode.pc,
			start:  start,
			end:    end,
		}
	}
}

func (ta *TaintAnalyzer) storageToStack(slot common.Hash) {
	if _, exists := ta.taintStorage[slot]; !exists {
		return
	}

	for _, taintOpcode := range ta.taintStorage[slot] {
		ta.AddTaintSource(taintOpcode.opcode, taintOpcode.pc)
	}
}

func (ta *TaintAnalyzer) stackToStorage(stackIndex int, slot common.Hash) {
	taintOpcodes, exists := ta.taintStacks[stackIndex]
	if !exists {
		return
	}

	for _, taintOpcode := range taintOpcodes {
		if taintOpcode != nil {
			ta.addTaintOpcodeToStorage(slot, taintOpcode.pc, taintOpcode.opcode)
		}
	}
}

func (ta *TaintAnalyzer) addTaintOpcodeToStorage(slot common.Hash, pc uint64, opcode byte) {
	if _, exists := ta.taintStorage[slot]; !exists {
		ta.taintStorage[slot] = make(TaintOpcodes)
	}

	t := &TaintOpcode{
		pc:     pc,
		opcode: opcode,
	}
	ta.taintStorage[slot][t.id()] = t
}
