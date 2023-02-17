//===--- SpecFuzzPass.cpp - Simulate conditional branch (mis)predictions -----===//
//
// Copyright: This file is distributed under the GPL version 3 License.
// See LICENSE for details.
//
//===------------------------------------------------------------------------===//
/// \file
///
/// A pass simulating conditional branch mispredictions and speculative
///   execution
///
/// The instrumentation consists of:
///   * making a checkpoint (specfuzz_chkp) before every conditional jump
///   * inserting a code sequence that simulates a misprediction
///   * counting the instructions executed during simulation
///   * rolling back (specfuzz_rlbk_*) to the latest checkpoint:
///     * either when the instruction counter reaches the threshold
///       (e.g., 250 instructions)
///     * or if we encounter a serializing instruction
///
/// In the file, the following abbreviations are used:
///   * flags: May clobber EFLAGS
///   * stack: May modify data on stack
///   * spec: May be executed speculatively
//===------------------------------------------------------------------------===//

#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "X86InstrInfo.h"
#include "X86Subtarget.h"
#include <stack>
#include <fstream>
#include <iostream>

#include "llvm/ADT/Statistic.h"
#include "llvm/Support/Debug.h"
#include "llvm/IR/DebugInfo.h"

using namespace llvm;

#define PASS_KEY "x86-specfuzz"
#define PASS_DESCRIPTION "Simulate Spectre v1 (Bounds Check Bypass)"
#define PASS_NAME "SpecFuzz"
#define DEBUG_TYPE PASS_KEY   // used internally by LLVM

static cl::opt<std::string> CollectInto(  // NOLINT
    PASS_KEY "-collect-functions-into",
    cl::desc(
        "Collect a list of functions to be instrumented into a file."
        " When set, the instrumentation is not applied."),
    cl::init(""), cl::Hidden);

static cl::opt<std::string> FunctionList(  // NOLINT
    PASS_KEY "-function-list",
    cl::desc(
        "A list of functions that will be instrumented."),
    cl::init(""), cl::Hidden);

static cl::opt<std::string> BranchList(  // NOLINT
    PASS_KEY "-branch-list",
    cl::desc(
        "If the flag is set, only the branches listed in this file will be instrumented"),
    cl::init(""), cl::Hidden);

static cl::opt<std::string> SerializationList(  // NOLINT
    PASS_KEY "-serialization-list",
    cl::desc(
        "If the flag is set, the listed locations will be treated as serialization points,"
        "as if an serializing instruction was inserted there"),
    cl::init(""), cl::Hidden);

static cl::opt<bool> CoverageOnly(  // NOLINT
    PASS_KEY "-coverage-only",
    cl::desc(
        "No simulation, only coverage. Inserts calls to specfuzz_cov"),
    cl::init(false), cl::Hidden);

namespace llvm {

void initializeX86SpecFuzzPassPass(PassRegistry &);

} // end namespace llvm

namespace {
class X86SpecFuzzPass : public MachineFunctionPass {
  public:
    static char ID;
    const X86InstrInfo *TII{};
    bool ListsInitialized = false;
    std::set<std::string> InstrumentedFunctions;
    bool SelectiveInstrumentation = false;
    bool HasExtraSerializationPoints = false;
    std::set<std::string> BranchesToInstrument;
    std::set<std::string> SerializationPoints;

    X86SpecFuzzPass() : MachineFunctionPass(ID) {
        initializeX86SpecFuzzPassPass(*PassRegistry::getPassRegistry());
    }

    auto getPassName() const -> StringRef override { return PASS_NAME; }
    auto runOnMachineFunction(MachineFunction &MF) -> bool override;

  private:
    int MinCheckInterval = 15;
    int NumInstructionsUntilNextCheck = 0;
    enum CallTargetType {
        InstrumentedTarget = 0,
        ExternalTarget = 1,
        ASanTarget = 2,
        ASanWrapperTarget = 3,
        IndirectTarget = 4,
    };
    unsigned TmpReg = X86::R15;

    auto visitFunction(MachineFunction &MF) -> bool;
    auto visitFunctionEntry(MachineInstr &MI, MachineBasicBlock &Parent) -> bool;
    auto visitBBEntry(MachineInstr &MI, MachineBasicBlock &Parent) -> bool;
    auto visitTerminator(MachineBasicBlock &Parent) -> bool;
    auto visitSpeculatableTerminator(MachineInstr &FirstJump,
                                     MachineBasicBlock &Parent,
                                     MachineInstr *SecondJump = nullptr,
                                     MachineInstr *ThirdJump = nullptr) -> bool;
    auto visitNonSpeculatableTerminator(MachineInstr &MI, MachineBasicBlock &Parent) -> bool;
    auto visitIndirectBranch(MachineInstr &MI, MachineBasicBlock &Parent) -> bool;
    auto visitReturn(MachineInstr &MI, MachineBasicBlock &Parent) -> bool;
    auto visitWrite(MachineInstr &MI, MachineBasicBlock &Parent) -> bool;
    auto visitPush(MachineInstr &MI, MachineBasicBlock &Parent) -> bool;
    auto visitCall(MachineInstr &MI, MachineBasicBlock &Parent) -> bool;
    auto visitSerializingInstruction(MachineInstr &MI, MachineBasicBlock &Parent) -> bool;
    auto visitInstrumentedCall(MachineInstr &MI, MachineBasicBlock &Parent) -> bool;
    auto visitExternalCall(MachineInstr &MI, MachineBasicBlock &Parent) -> bool;
    auto visitIndirectCall(MachineInstr &Call, MachineBasicBlock &Parent) -> bool;
    auto visitASanCall(MachineInstr &MI, MachineBasicBlock &Parent) -> bool;
    auto insertAdditionalCheck(MachineInstr &MI, MachineBasicBlock &Parent, int Offset) -> bool;

    // Simple Coverage sub-pass
    auto coveragePass(MachineFunction &MF) -> bool;

    // Helper functions
    auto getCallTargetType(MachineInstr &MI) -> CallTargetType;
    auto countRealInstructions(MachineBasicBlock &MBB) -> int;
    void addCallRuntimeFunction(MachineBasicBlock &MBB,
                                MachineInstr &MI,
                                DebugLoc &Loc,
                                const char *FunctionName);
    void preserveRegister(MachineBasicBlock &Parent,
                          MachineInstr &InsertBefore,
                          DebugLoc &DL,
                          unsigned Register,
                          const char *Location);
    void preserveRegister(MachineBasicBlock &Parent,
                          MachineBasicBlock::iterator InsertBefore,
                          DebugLoc &DL,
                          unsigned Register,
                          const char *Location);
    void restoreRegister(MachineBasicBlock &Parent,
                         MachineInstr &InsertBefore,
                         DebugLoc &DL,
                         unsigned Register,
                         const char *Location);
    void restoreRegister(MachineBasicBlock &Parent,
                         MachineBasicBlock::iterator InsertBefore,
                         DebugLoc &DL,
                         unsigned Register,
                         const char *Location);
    auto reverseJump(unsigned int Opcode) -> unsigned;

    static auto isFirstInFusedPair(MachineInstr &MI) -> bool;
    static auto splitMBBAt(MachineBasicBlock &CurMBB,
                           MachineBasicBlock::iterator SplitAt) -> MachineBasicBlock *;
    static auto isSerializingInstruction(MachineInstr &MI) -> bool;
    static auto isAcquireOrRelease(unsigned Opcode) -> bool;
    static auto isExplicitlySerializing(unsigned Opcode) -> bool;
    static auto isPush(unsigned Opcode) -> int;
    static auto getCompleteDebugLocation(DebugLoc &Loc) -> std::string;
    static void readIntoList(std::string &File, std::set<std::string> *List);
};

} // end of anonymous namespace

char X86SpecFuzzPass::ID = 0;

/// Parse and process compilation flags
auto X86SpecFuzzPass::runOnMachineFunction(MachineFunction &MF) -> bool {
    LLVM_DEBUG(dbgs() << "******** " << getPassName() << " : " << MF.getName() << " ********\n");

    const auto &SubTarget = MF.getSubtarget<X86Subtarget>();
    TII = SubTarget.getInstrInfo();

    // Parse arguments:
    if (CoverageOnly) {
        return coveragePass(MF);
    }

    if (not CollectInto.empty()) {
        std::ofstream outFile(CollectInto.getValue().c_str(), std::ios_base::app);
        outFile << MF.getName().str() << '\n';
        outFile.close();
        return false;
    }

    if (not FunctionList.empty()) {
        readIntoList(FunctionList, &InstrumentedFunctions);
        assert(InstrumentedFunctions.count(MF.getName().str()));
    } else {
        // if the list of instrumented functions is not provided, then all calls are considered
        // as calls to non-instrumented functions, except recursive calls
        InstrumentedFunctions.insert(MF.getName().str());
    }

    if (not ListsInitialized) {
        if (not BranchList.empty()) {
            SelectiveInstrumentation = true;
            readIntoList(BranchList, &BranchesToInstrument);
        }
        if (not SerializationList.empty()) {
            HasExtraSerializationPoints = true;
            readIntoList(SerializationList, &SerializationPoints);
        }
        ListsInitialized = true;
    }

    return visitFunction(MF);
}

auto X86SpecFuzzPass::visitFunction(MachineFunction &MF) -> bool {
    bool Modified = false;

    // We're not interested in empty functions
    if (MF.begin() == MF.end())
        return Modified;

    // Blacklist functions
    // TBD: implement proper blacklisting
    if (MF.getName().contains("asan")) {
        LLVM_DEBUG(dbgs() << "Blacklisted\n");
        return Modified;
    }

    // Iterate over all instructions
    // Note that we first create a list of original basic blocks, and then iterate over it.
    // We do not iterate over the block directly, as in the process, we add new BBs to the function
    std::vector<MachineBasicBlock *> OriginalMBBs;
    for (auto &MBB : MF)
        OriginalMBBs.push_back(&MBB);

    bool FirstInstructionInFunction = true;
    for (auto &MBB : OriginalMBBs) {
        std::vector<MachineInstr *> OriginalMIs;
        for (MachineInstr &MI : *MBB)
            OriginalMIs.push_back(&MI);

        bool FirstInstructionInBB = true;
        NumInstructionsUntilNextCheck = countRealInstructions(*MBB);

        for (MachineInstr *MI : OriginalMIs) {
            // We ignore virtual instructions
            if (MI->isMetaInstruction())
                continue;
            if (not isFirstInFusedPair(*MI))
                NumInstructionsUntilNextCheck--;

            if (FirstInstructionInFunction) {
                Modified |= visitFunctionEntry(*MI, *MBB);
                FirstInstructionInFunction = false;
            }

            // The first instruction in the BB
            if (FirstInstructionInBB && not MI->isTerminator()) {
                Modified |= visitBBEntry(*MI, *MBB);
                FirstInstructionInBB = false;
                // no 'continue' here; the first instruction could be also a write or a call
            }

            // Serializing instruction
            if (isSerializingInstruction(*MI)) {
                Modified |= visitSerializingInstruction(*MI, *MBB);
                continue;
            }

            // Store instruction
            if (MI->mayStore()) {
                Modified |= visitWrite(*MI, *MBB);
                continue;
            }

            // Calls
            if (MI->isCall()) {
                Modified |= visitCall(*MI, *MBB);
                continue;
            }

            // Terminators
            if (MI->isTerminator()) {
                Modified |= visitTerminator(*MBB);
                break;
            }

            // In the middle of a very long BB
            if (NumInstructionsUntilNextCheck <= 0 &&
                TII->isSafeToClobberEFLAGS(*MBB, MI)) {
                Modified |= insertAdditionalCheck(*MI, *MBB, NumInstructionsUntilNextCheck);
                NumInstructionsUntilNextCheck =
                    MinCheckInterval + NumInstructionsUntilNextCheck + 1;
            }
        }
    }

    // Initialize Branch Table
    // This code is intentionally put here, after all other instrumentations so that we
    // avoid interfering with other parts of the pass
    if (MF.getName() == "main") {
        LLVM_DEBUG(dbgs() << "Initializing Branch Table\n");
        MachineBasicBlock &FirstMBB = *MF.begin();
        MachineInstr &FirstMI = *FirstMBB.getFirstNonDebugInstr();
        BuildMI(FirstMBB, FirstMI, FirstMI.getDebugLoc(), TII->get(X86::CALLpcrel32))
            .addExternalSymbol("specfuzz_init");
    }

    return Modified;
}

/// Add a special NOP before the function to be able to recognise instrumented
/// functions at runtime
/// CLOB: spec
auto X86SpecFuzzPass::visitFunctionEntry(MachineInstr &MI, MachineBasicBlock &Parent) -> bool {
    LLVM_DEBUG(dbgs() << "Instrumenting function entry: " << MI);
    DebugLoc Loc = MI.getDebugLoc();

    // NOPL 0x42(RBX)
    BuildMI(Parent, MI, Loc, TII->get(X86::NOOPL))
        .addReg(X86::RBX).addImm(1)
        .addReg(0).addImm(42)
        .addReg(0);
    return true;
}

/// Decrement the global instruction counter in the beginning of every basic block
/// CLOB: spec
auto X86SpecFuzzPass::visitBBEntry(MachineInstr &MI,
                                   MachineBasicBlock &Parent) -> bool {
    LLVM_DEBUG(dbgs() << "Instrumenting BB entry: " << MI);
    DebugLoc Loc = MI.getDebugLoc();

    if (NumInstructionsUntilNextCheck == 0) {
        LLVM_DEBUG(dbgs() << "  Zero-sized BB, skipping." << MI);
        return false;
    }

    // We cannot add the increment if it may clobber EFLAGS.
    // Instead, we skip the BB. It will lead to overestimation sometimes,
    // but in the worst case it will cause a false positive, not a false negative.
    if (not TII->isSafeToClobberEFLAGS(Parent, &MI)) {
        LLVM_DEBUG(dbgs() << "  May clobber EFLAGS, skipping." << MI);
        return false;
    }

    // SUB parentSize, instruction_counter
    BuildMI(Parent, MI, Loc, TII->get(X86::SUB64mi8))
        .addReg(0).addImm(1)
        .addReg(0).addExternalSymbol("instruction_counter")
        .addReg(0).addImm(NumInstructionsUntilNextCheck);
    return true;
}

/// Find out the type of the terminators in the current basic block and
/// add the appropriate instrumentation.
/// If targeted instrumentation is enabled, instrument accordingly
auto X86SpecFuzzPass::visitTerminator(MachineBasicBlock &Parent) -> bool {
    long NumTerminators = std::distance(Parent.terminators().begin(), Parent.terminators().end());
    auto Terminators = Parent.terminators().begin();
    MachineInstr &FirstTerminator = *Terminators;

    // TODO: this function is ugly and needs refactoring
    if (SelectiveInstrumentation) {
        DebugLoc Loc = FirstTerminator.getDebugLoc();
        std::string LocName = getCompleteDebugLocation(Loc);
        if (BranchesToInstrument.count(LocName) == 0) {
            LLVM_DEBUG(
                dbgs() << "Branch is not in the instrumentation list: " << LocName << "\n");
            return visitNonSpeculatableTerminator(FirstTerminator, Parent);
        }
    }

    if (HasExtraSerializationPoints) {
        DebugLoc Loc = FirstTerminator.getDebugLoc();
        std::string LocName = getCompleteDebugLocation(Loc);
        if (SerializationPoints.count(LocName) != 0) {
            LLVM_DEBUG(
                dbgs() << "Branch is marked as patched: " << LocName << "\n");
            addCallRuntimeFunction(Parent, FirstTerminator, Loc, "specfuzz_rlbk_patched");
            return true;
        }
    }

    switch (NumTerminators) {
        case 1:
            return FirstTerminator.isConditionalBranch() ?
                   visitSpeculatableTerminator(FirstTerminator, Parent) :
                   visitNonSpeculatableTerminator(FirstTerminator, Parent);
        case 2: {
            MachineInstr &SecondTerminator = *(++Terminators);
            return visitSpeculatableTerminator(FirstTerminator, Parent, &SecondTerminator);
        }
        case 3: {
            MachineInstr &SecondTerminator = *(++Terminators);
            MachineInstr &ThirdTerminator = *(++Terminators);
            return visitSpeculatableTerminator(FirstTerminator,
                                               Parent,
                                               &SecondTerminator,
                                               &ThirdTerminator);
        }
        default:
            llvm_unreachable("Not supported terminator type");
    }
}

/// When we encounter a conditional branch, we replace it with a simulation of misprediction.
/// That is, we call the checkpoint function (specfuzz_chkp) and insert a sequence of jumps
/// that changes the original control flow. During the simulation, this sequence directs the
/// control flow to the wrong branch, and outside the simulation - to the correct branch.
/// CLOB: spec
auto X86SpecFuzzPass::visitSpeculatableTerminator(MachineInstr &FirstJump,
                                                  MachineBasicBlock &Parent,
                                                  MachineInstr *SecondJump,
                                                  MachineInstr *ThirdJump) -> bool {
    LLVM_DEBUG(dbgs() << "Instrumenting a conditional branch: " << FirstJump);
    DebugLoc Loc = FirstJump.getDebugLoc();

    // Start by finding out the successors of the BB.
    // The first successor is always the target of the first jump
    MachineBasicBlock *FirstJumpTarget = FirstJump.getOperand(0).getMBB();

    // The second and, potentially, later successors depend on the second jump.
    // We have 4 options here: there's no second jump, the jump is a unconditional jump,
    // it is a conditional jump, and there's a third unconditional jump. Conditional third
    // jump as well as their combinations are not supported.
    // Note: yes, I know, the following code is not very efficient. But it's the only way to
    // keep it understandable
    MachineBasicBlock *SecondJumpTarget = nullptr;
    MachineBasicBlock *FallThroughTarget = nullptr;

    // 1) No second jump:
    if (Parent.canFallThrough()) {
        FallThroughTarget = Parent.getFallThrough();
    }

    // 2) Unconditional second jump:
    if (SecondJump and not SecondJump->isConditionalBranch()) {
        FallThroughTarget = SecondJump->getOperand(0).getMBB();
    }

    // 3) Conditional second jump:
    if (SecondJump and SecondJump->isConditionalBranch()) {
        SecondJumpTarget = SecondJump->getOperand(0).getMBB();
    }

    // 4) Unconditional third jump:
    if (ThirdJump) {
        assert(SecondJump->isConditionalBranch());
        FallThroughTarget = ThirdJump->getOperand(0).getMBB();
    }
    assert(FallThroughTarget != nullptr);

    // A workaround for a bug (feature?) in LLVM:
    // Sometimes, LLVM might leave a conditional jump to an unreachable BB
    // if the condition never holds. These cases normally work fine as
    // the jump is never triggered at runtime. But, if we add a simulated
    // misprediction, it diverts the control flow into strange places.
    // To avoid it, do not instrument such conditional jumps
    if (FirstJumpTarget->succ_empty() && not FirstJumpTarget->isReturnBlock()) {
        // TODO: report these instances
        return false;
    }
    assert(SecondJumpTarget == nullptr || !SecondJumpTarget->succ_empty()
               || SecondJumpTarget->isReturnBlock());

    // Finally, the instrumentation itself:
    // Add an invocation of the checkpoint function
    addCallRuntimeFunction(Parent, FirstJump, Loc, "specfuzz_chkp");

    // Add a simulation of a misprediction:
    // - Move the conditional jumps into a separate basic block
    MachineBasicBlock
        *OriginalJumpsMBB = splitMBBAt(Parent, (MachineBasicBlock::iterator) &FirstJump);

    // - Add an unconditional jump for skipping the simulation
    BuildMI(&Parent, Loc, TII->get(X86::JMP_1))
        .addMBB(OriginalJumpsMBB);

    // - Add reversed jumps and a fallthrough
    unsigned ReversedJump = reverseJump(FirstJump.getOpcode());
    BuildMI(&Parent, Loc, TII->get(ReversedJump)).addMBB(FirstJumpTarget);

    if (SecondJumpTarget) {
        unsigned SecondReversedJump = reverseJump(SecondJump->getOpcode());
        BuildMI(&Parent, Loc, TII->get(SecondReversedJump)).addMBB(SecondJumpTarget);
    }

    BuildMI(&Parent, Loc, TII->get(X86::JMP_1)).addMBB(FallThroughTarget);

    return true;
}

/// When the BB does not terminate with a conditional branch, it cannot be speculated.
/// Thus, we only check if it is time to rollback
///
/// COND: spec
auto X86SpecFuzzPass::visitNonSpeculatableTerminator(MachineInstr &MI,
                                                     MachineBasicBlock &Parent) -> bool {
    if (MI.isIndirectBranch()) {
        return visitIndirectBranch(MI, Parent);
    }

    if (MI.isReturn()) {
        return visitReturn(MI, Parent);
    }

    DebugLoc Loc = MI.getDebugLoc();
    LLVM_DEBUG(dbgs() << "Instrumenting an unconditional terminator: " << MI);
    addCallRuntimeFunction(Parent, MI, Loc, "specfuzz_rlbk_if_done");
    return true;
}

/// Indirect branches are a special case.
/// Since the jump address could be speculatively corrupted, we have to first check the address
/// before executing the jump.
///
/// We assume that the jump will not cross the function boundaries, or will at least jump into
/// an instrumented code region. I have yet to come up with a way to avoid this assumption.
///
/// COND: spec
auto X86SpecFuzzPass::visitIndirectBranch(MachineInstr &MI, MachineBasicBlock &Parent) -> bool {
    LLVM_DEBUG(dbgs() << "Instrumenting an indirect branch: " << MI);
    DebugLoc Loc = MI.getDebugLoc();

    preserveRegister(Parent, MI, Loc, X86::RDI, "tmp_gpr1");

    // Move the jump address into RDI for checking
    // Note: this switch only handles 64-bit addresses. Not sure if Clang can generate
    // other sizes. If it ever does, the corresponding cases would need to be
    // added.
    switch (MI.getOpcode()) {
        case X86::JMP64r:
            BuildMI(Parent, MI, Loc, TII->get(X86::MOV64rr), X86::RDI)
                .addReg(MI.getOperand(0).getReg());
            break;
        case X86::JMP64m:
            BuildMI(Parent, MI, Loc, TII->get(X86::MOV64rm), X86::RDI)
                .add(MI.getOperand(X86::AddrBaseReg))
                .add(MI.getOperand(X86::AddrScaleAmt))
                .add(MI.getOperand(X86::AddrIndexReg))
                .add(MI.getOperand(X86::AddrDisp))
                .add(MI.getOperand(X86::AddrSegmentReg));
            break;
        default:
            llvm_unreachable("Unexpected indirect jump type");
    }

    // Check if the pointer has been speculatively corrupted
    addCallRuntimeFunction(Parent, MI, Loc, "specfuzz_check_code_pointer");
    restoreRegister(Parent, MI, Loc, X86::RDI, "tmp_gpr1");
    return true;
}

/// Similarly to indirect branches, we have to check that the return address was not corrupted
/// by speculative execution
///
/// COND: spec
auto X86SpecFuzzPass::visitReturn(MachineInstr &MI, MachineBasicBlock &Parent) -> bool {
    LLVM_DEBUG(dbgs() << "Instrumenting a return: " << MI);
    DebugLoc Loc = MI.getDebugLoc();

    preserveRegister(Parent, MI, Loc, X86::RDI, "tmp_gpr1");
    BuildMI(Parent, MI, Loc, TII->get(X86::MOV64rm), X86::RDI)
        .addReg(X86::RSP).addImm(1)
        .addReg(0).addImm(0)
        .addReg(0);
    addCallRuntimeFunction(Parent, MI, Loc, "specfuzz_check_code_pointer");
    restoreRegister(Parent, MI, Loc, X86::RDI, "tmp_gpr1");

    //addCallRuntimeFunction(Parent, MI, Loc, "specfuzz_rlbk_if_done");
    return true;
}

/// Before writing a value to memory, we store the old value and the address on a
/// dedicated store stack
/// CLOB: spec
///
/// Example:
///     Before                     |   After
/// ---------------------------------------------------------------------------------------------
///                                |    MOVQ %rsp, current_rsp  // change stack
///                                |    MOVQ %r15, tmp_gpr1  // reserve the value of r15
///                                |    LEAQ 8(%rsp), %r15      // store the address
///                                |    MOVQ checkpoint_sp, %rsp
///                                |    PUSH %r15
///                                |    PUSH (%r15)             // store the original value
///                                |    MOVQ %rsp, checkpoint_sp     // restore stack
///                                |    MOVQ tmp_gpr1, %r15
///                                |    MOVQ current_rsp, %rsp
///     MOV    %rbx, 8(%rsp)       |    MOV  %rbx, 8(%rsp)
/// ---------------------------------------------------------------------------------------------
auto X86SpecFuzzPass::visitWrite(MachineInstr &MI, MachineBasicBlock &Parent) -> bool {
    // Pushes are a special case as the address is always in RSP
    if (isPush(MI.getOpcode()))
        return visitPush(MI, Parent);

    LLVM_DEBUG(dbgs() << "Instrumenting store: " << MI);
    DebugLoc Loc = MI.getDebugLoc();

    const MCInstrDesc &Desc = MI.getDesc();
    unsigned Flags = MI.getFlags();
    assert(not(Flags & X86::IP_HAS_REPEAT) && "REP prefix is not supported");
    assert(not(Flags & X86::IP_HAS_REPEAT_NE) && "REPNE prefix is not supported");

    // Define, where the memory reference begins
    int MemRefBegin = X86II::getMemoryOperandNo(Desc.TSFlags);
    if (MemRefBegin < 0 && isAcquireOrRelease(MI.getOpcode()))
        MemRefBegin = 0; // It's a workaround for LLVM atomic write pseudo-instructions
    assert(MemRefBegin >= 0 && "Not a write instruction");
    MemRefBegin += X86II::getOperandBias(Desc);  // NOLINT

    preserveRegister(Parent, MI, Loc, X86::RSP, "current_rsp");
    preserveRegister(Parent, MI, Loc, TmpReg, "tmp_gpr1");

    // LEAQ write_address, %TmpReg
    BuildMI(Parent, MI, Loc, TII->get(X86::LEA64r), TmpReg)
        .add(MI.getOperand(MemRefBegin + X86::AddrBaseReg))
        .add(MI.getOperand(MemRefBegin + X86::AddrScaleAmt))
        .add(MI.getOperand(MemRefBegin + X86::AddrIndexReg))
        .add(MI.getOperand(MemRefBegin + X86::AddrDisp))
        .add(MI.getOperand(MemRefBegin + X86::AddrSegmentReg));

    restoreRegister(Parent, MI, Loc, X86::RSP, "checkpoint_sp");
	
	MachineMemOperand *MMO = *MI.memoperands_begin();
    uint64_t width = MMO->getSize();
	
	LLVM_DEBUG(dbgs() << "Store's width: " << width << "\n");
	
	BuildMI(Parent, MI, Loc, TII->get(X86::PUSH64i8))
		.addImm((width > 8)? 8 : width);
	
    // PUSH %TmpReg
    BuildMI(Parent, MI, Loc, TII->get(X86::PUSH64r), TmpReg);
	
	
	switch (width) {
		case 1:
			preserveRegister(Parent, MI, Loc, X86::R14, "tmp_gpr2");
			
			// Immediate is arbitrary
			BuildMI(Parent, MI, Loc, TII->get(X86::PUSH64i8))
				.addImm(0);
			
			BuildMI(Parent, MI, Loc, TII->get(X86::MOV8rm), X86::R14B)
				.addReg(TmpReg).addImm(1)
				.addReg(0).addImm(0)
				.addReg(0);
			
			BuildMI(Parent, MI, Loc, TII->get(X86::MOV8mr))
				.addReg(X86::RSP).addImm(1)
				.addReg(0).addImm(0)
				.addReg(0)
				.addReg(X86::R14B);
				
			restoreRegister(Parent, MI, Loc, X86::R14, "tmp_gpr2");
			
			break;
		
		case 2:
			preserveRegister(Parent, MI, Loc, X86::R14, "tmp_gpr2");
			
			// Immediate is arbitrary
			BuildMI(Parent, MI, Loc, TII->get(X86::PUSH64i8))
				.addImm(0);
			
			BuildMI(Parent, MI, Loc, TII->get(X86::MOV16rm), X86::R14W)
				.addReg(TmpReg).addImm(1)
				.addReg(0).addImm(0)
				.addReg(0);
			
			BuildMI(Parent, MI, Loc, TII->get(X86::MOV16mr))
				.addReg(X86::RSP).addImm(1)
				.addReg(0).addImm(0)
				.addReg(0)
				.addReg(X86::R14W);
				
			restoreRegister(Parent, MI, Loc, X86::R14, "tmp_gpr2");
				
			break;
			
		case 4:
			preserveRegister(Parent, MI, Loc, X86::R14, "tmp_gpr2");
			
			// Immediate is arbitrary
			BuildMI(Parent, MI, Loc, TII->get(X86::PUSH64i8))
				.addImm(0);
			
			BuildMI(Parent, MI, Loc, TII->get(X86::MOV32rm), X86::R14D)
				.addReg(TmpReg).addImm(1)
				.addReg(0).addImm(0)
				.addReg(0);
			
			BuildMI(Parent, MI, Loc, TII->get(X86::MOV32mr))
				.addReg(X86::RSP).addImm(1)
				.addReg(0).addImm(0)
				.addReg(0)
				.addReg(X86::R14D);
				
			restoreRegister(Parent, MI, Loc, X86::R14, "tmp_gpr2");
				
			break;
				
		case 8:
		case 16:
		case 32:
			// PUSH (%TmpReg)
			BuildMI(Parent, MI, Loc, TII->get(X86::PUSH64rmm), TmpReg)
				.addImm(1).addReg(0)
				.addImm(0).addReg(0);
			
			if (width == 8) break;
			
			BuildMI(Parent, MI, Loc, TII->get(X86::LEA64r), TmpReg)
            .addReg(TmpReg).addImm(1)
            .addReg(0).addImm(8)
            .addReg(0);
			
			BuildMI(Parent, MI, Loc, TII->get(X86::PUSH64i8))
				.addImm(8);

			// PUSH %TmpReg
			BuildMI(Parent, MI, Loc, TII->get(X86::PUSH64r), TmpReg);

			// PUSH (%TmpReg)
			BuildMI(Parent, MI, Loc, TII->get(X86::PUSH64rmm), TmpReg)
				.addImm(1).addReg(0)
				.addImm(0).addReg(0);
		
			if (width == 16) { LLVM_DEBUG(dbgs() << "   The store is 128-bit wide\n"); break; }
			
			BuildMI(Parent, MI, Loc, TII->get(X86::LEA64r), TmpReg)
            .addReg(TmpReg).addImm(1)
            .addReg(0).addImm(8)
            .addReg(0);
			
			BuildMI(Parent, MI, Loc, TII->get(X86::PUSH64i8))
				.addImm(8);

			// PUSH %TmpReg
			BuildMI(Parent, MI, Loc, TII->get(X86::PUSH64r), TmpReg);

			// PUSH (%TmpReg)
			BuildMI(Parent, MI, Loc, TII->get(X86::PUSH64rmm), TmpReg)
				.addImm(1).addReg(0)
				.addImm(0).addReg(0);
				
			LLVM_DEBUG(dbgs() << "   The store is 256-bit wide\n"); 
			break;
		
		default:
			llvm_unreachable("Unknown width");
			break;
	}

    // SSE stores are 128-bit wide
    /*if (Desc.TSFlags >> X86II::SSEDomainShift & 3) {  // NOLINT
        LLVM_DEBUG(dbgs() << "   The store is 128-bit wide\n");

        // LEAQ 8(%TmpReg), %TmpReg
        BuildMI(Parent, MI, Loc, TII->get(X86::LEA64r), TmpReg)
            .addReg(TmpReg).addImm(1)
            .addReg(0).addImm(8)
            .addReg(0);
			
		BuildMI(Parent, MI, Loc, TII->get(X86::PUSH64i8))
			.addImm(8);

        // PUSH %TmpReg
        BuildMI(Parent, MI, Loc, TII->get(X86::PUSH64r), TmpReg);

        // PUSH (%TmpReg)
        BuildMI(Parent, MI, Loc, TII->get(X86::PUSH64rmm), TmpReg)
            .addImm(1).addReg(0)
            .addImm(0).addReg(0);
    }*/

    preserveRegister(Parent, MI, Loc, X86::RSP, "checkpoint_sp");
    restoreRegister(Parent, MI, Loc, TmpReg, "tmp_gpr1");
    restoreRegister(Parent, MI, Loc, X86::RSP, "current_rsp");

    return true;
}

/// Same as the instrumentation of writes, but the address is always in RSP
/// CLOB: spec
auto X86SpecFuzzPass::visitPush(MachineInstr &MI, MachineBasicBlock &Parent) -> bool {
    LLVM_DEBUG(dbgs() << "Instrumenting a push or call: " << MI);
    DebugLoc Loc = MI.getDebugLoc();

    preserveRegister(Parent, MI, Loc, X86::RSP, "current_rsp");
    preserveRegister(Parent, MI, Loc, TmpReg, "tmp_gpr1");

    // LEAQ -8(%rsp), %TmpReg
    BuildMI(Parent, MI, Loc, TII->get(X86::LEA64r), TmpReg)
        .addReg(X86::RSP).addImm(1)
        .addReg(0).addImm(-8)
        .addReg(0);

    restoreRegister(Parent, MI, Loc, X86::RSP, "checkpoint_sp");

	BuildMI(Parent, MI, Loc, TII->get(X86::PUSH64i8))
		.addImm(8);

    // PUSH %TmpReg
    BuildMI(Parent, MI, Loc, TII->get(X86::PUSH64r), TmpReg);

    // PUSH (%TmpReg)
    BuildMI(Parent, MI, Loc, TII->get(X86::PUSH64rmm), TmpReg)
        .addImm(1).addReg(0)
        .addImm(0).addReg(0);

    preserveRegister(Parent, MI, Loc, X86::RSP, "checkpoint_sp");
    restoreRegister(Parent, MI, Loc, TmpReg, "tmp_gpr1");
    restoreRegister(Parent, MI, Loc, X86::RSP, "current_rsp");

    return true;
}

/// Instrumentation of calls
/// Depends on the call target type. See details inline
auto X86SpecFuzzPass::visitCall(MachineInstr &MI, MachineBasicBlock &Parent) -> bool {
    switch (getCallTargetType(MI)) {
        case InstrumentedTarget:
            // Calls to instrumented functions don't require any special handling and
            // we only need to store the top of the stack, which the call overwrites
            // (i.e., we have the same instrumentation here as with pushes)
            return visitInstrumentedCall(MI, Parent);
        case ExternalTarget:
        case ASanWrapperTarget:
            return visitExternalCall(MI, Parent);
        case IndirectTarget:
            return visitIndirectCall(MI, Parent);
        case ASanTarget:
            return visitASanCall(MI, Parent);
        default:
            llvm_unreachable("Unexpected TargetType");
    }
}

/// Same as the instrumentation of pushes
/// CLOB: spec
auto X86SpecFuzzPass::visitInstrumentedCall(MachineInstr &MI, MachineBasicBlock &Parent) -> bool {
    return visitPush(MI, Parent);
}

/// Handling calls to non-instrumented functions
/// Since we don't have instrumentation in external functions, we must terminate simulation
/// before the call. In addition, we must disable future simulations before calling the
/// function. We do it to avoid simulation in callback functions, that is, instrumented
/// functions that are called by non-instrumented ones.
/// Correspondingly, we have to re-enable the simulation after returning from the call
/// CLOB: spec flags
auto X86SpecFuzzPass::visitExternalCall(MachineInstr &MI, MachineBasicBlock &Parent) -> bool {
    LLVM_DEBUG(dbgs() << "Instrumenting a call to an external function: " << MI);
    DebugLoc Loc = MI.getDebugLoc();

    addCallRuntimeFunction(Parent, MI, Loc, "specfuzz_rlbk_external_call");

    // disable before
    BuildMI(Parent, MI, Loc, TII->get(X86::ADD16mi))
        .addReg(0).addImm(1)
        .addReg(0).addExternalSymbol("disable_speculation")
        .addReg(0).addImm(1);

    // re-enable after
    MachineBasicBlock::iterator Next = MI.getNextNode() ? *MI.getNextNode() : Parent.end();

    BuildMI(Parent, Next, Loc, TII->get(X86::SUB16mi))
        .addReg(0).addImm(1)
        .addReg(0).addExternalSymbol("disable_speculation")
        .addReg(0).addImm(1);

    return true;
}

/// Read the first instruction of the callee. If it is a 'special' NOP, it means that
/// we're calling an instrumented function and we don't have to do anything.
/// Otherwise, it is a non-instrumented code and we have to disable simulation in it
/// to prevent state corruption.
///
/// TODO: refactor me! plz!
auto X86SpecFuzzPass::visitIndirectCall(MachineInstr &Call, MachineBasicBlock &Parent) -> bool {
    LLVM_DEBUG(dbgs() << "Instrumenting an indirect call: " << Call);
    DebugLoc Loc = Call.getDebugLoc();

    // we always stop simulation before indirect calls
    // TODO: make dynamically define if we indeed need to rollback
    addCallRuntimeFunction(Parent, Call, Loc, "specfuzz_rlbk_indirect_call");

    // define the call type
    unsigned FunctionPointerReg;
    bool PointerIsInMemory;
    switch (Call.getOpcode()) {
        case X86::CALL64r:
            FunctionPointerReg = Call.getOperand(0).getReg();
            PointerIsInMemory = false;
            break;
        case X86::CALL64m:
            FunctionPointerReg = X86::R14;
            PointerIsInMemory = true;
            break;
        default:
            llvm_unreachable("Unexpected indirect call type");
    }

    // Before call:

    // We need two registers for this instrumentation:
    preserveRegister(Parent, Call, Loc, X86::RDI, "tmp_gpr1");
    preserveRegister(Parent, Call, Loc, X86::R14, "tmp_gpr2");

    // if the function pointer is in memory, we first fetch it
    if (PointerIsInMemory) {
        BuildMI(Parent, Call, Loc, TII->get(X86::MOV64rm), FunctionPointerReg)
            .add(Call.getOperand(X86::AddrBaseReg))
            .add(Call.getOperand(X86::AddrScaleAmt))
            .add(Call.getOperand(X86::AddrIndexReg))
            .add(Call.getOperand(X86::AddrDisp))
            .add(Call.getOperand(X86::AddrSegmentReg));
    }

    // Check if the pointer has been speculatively corrupted
    BuildMI(Parent, Call, Loc, TII->get(X86::MOV64rr), X86::RDI)
        .addReg(FunctionPointerReg);
    addCallRuntimeFunction(Parent, Call, Loc, "specfuzz_check_code_pointer");

    // Find out the function type
    // CMP expected_opcode, *function_pointer  ; is the first instruction a NOP?
    // SETNE r14b  ; if yes, set r14b to 1
    // AND 0x0f, r14w  ; clear the higher 8 bits (they are not set by SETNE)
    BuildMI(Parent, Call, Loc, TII->get(X86::CMP32mi))
        .addReg(FunctionPointerReg).addImm(1)
        .addReg(0).addImm(0)
        .addReg(0).addImm(0x2a431f0f);  // nopl   42(%rbx)
    BuildMI(Parent, Call, Loc, TII->get(X86::SETNEr), X86::R14B);
    BuildMI(Parent, Call, Loc, TII->get(X86::AND16ri8), X86::R14W)
        .addReg(X86::R14W).addImm(15);

    // For non-instrumented functions, disable speculation
    // ADD r14w, disable_speculation
    BuildMI(Parent, Call, Loc, TII->get(X86::ADD16mr))
        .addReg(0).addImm(1)
        .addReg(0).addExternalSymbol("disable_speculation")
        .addReg(0).addReg(X86::R14W);

    // preserve the result of comparison:
    // MOV specfuzz_call_type_stack_sp, rdi
    // MOV bx, (rdi)
    // SUBQ $2, (specfuzz_call_type_stack_sp)
    BuildMI(Parent, Call, Loc, TII->get(X86::MOV64rm), X86::RDI)
        .addReg(0).addImm(1)
        .addReg(0).addExternalSymbol("specfuzz_call_type_stack_sp")
        .addReg(0);
    BuildMI(Parent, Call, Loc, TII->get(X86::MOV16mr))
        .addReg(X86::RDI).addImm(1)
        .addReg(0).addImm(0)
        .addReg(0).addReg(X86::R14W);
    BuildMI(Parent, Call, Loc, TII->get(X86::SUB64mi8))
        .addReg(0).addImm(1)
        .addReg(0).addExternalSymbol("specfuzz_call_type_stack_sp")
        .addReg(0).addImm(2);

    // restore the register values
    restoreRegister(Parent, Call, Loc, X86::R14, "tmp_gpr2");
    restoreRegister(Parent, Call, Loc, X86::RDI, "tmp_gpr1");

    // After the call:
    // fetch the stored comparison result and subtract it from disable_speculation
    //
    // MOVQ r14, tmp_gpr2
    // ADDQ $2, specfuzz_call_type_stack_sp
    // MOV specfuzz_call_type_stack_sp, r14
    // MOVS (r14), r14w
    // SUBQ r14w, disable_speculation
    // MOVQ tmp_gpr2, r14

    // COND: SPEC NSTACK
    MachineBasicBlock::iterator Next = Call.getNextNode() ? *Call.getNextNode() : Parent.end();

    preserveRegister(Parent, Next, Loc, X86::R14, "tmp_gpr2");
    BuildMI(Parent, Next, Loc, TII->get(X86::ADD64mi8))
        .addReg(0).addImm(1)
        .addReg(0).addExternalSymbol("specfuzz_call_type_stack_sp")
        .addReg(0).addImm(2);

    BuildMI(Parent, Next, Loc, TII->get(X86::MOV64rm), X86::R14)
        .addReg(0).addImm(1)
        .addReg(0).addExternalSymbol("specfuzz_call_type_stack_sp")
        .addReg(0);

    BuildMI(Parent, Next, Loc, TII->get(X86::MOV16rm))
        .addReg(X86::R14W)
        .addReg(X86::R14).addImm(1)
        .addReg(0).addImm(0)
        .addReg(0);

    // Clear the higher bits to avoid overflows if this code is executed speculatively
    BuildMI(Parent, Next, Loc, TII->get(X86::AND16ri8), X86::R14W)
        .addReg(X86::R14W).addImm(15);

    BuildMI(Parent, Next, Loc, TII->get(X86::SUB16mr))
        .addReg(0).addImm(1)
        .addReg(0).addExternalSymbol("disable_speculation")
        .addReg(0).addReg(X86::R14W);
    restoreRegister(Parent, Next, Loc, X86::R14, "tmp_gpr2");
    return true;
}

/// ASan functions must be stack-neutral and thus, we have to switch the stack
/// CLOB: spec
auto X86SpecFuzzPass::visitASanCall(MachineInstr &MI, MachineBasicBlock &Parent) -> bool {
    LLVM_DEBUG(dbgs() << "Instrumenting a call to an ASan function: " << MI);
    DebugLoc Loc = MI.getDebugLoc();

    // store the stack pointer before the call
    preserveRegister(Parent, MI, Loc, X86::RSP, "current_rsp");

    BuildMI(Parent, MI, Loc, TII->get(X86::LEA64r))
        .addReg(X86::RSP)
        .addReg(0).addImm(1)
        .addReg(0).addExternalSymbol("asan_rtl_frame")
        .addReg(0);

    // restore after
    MachineBasicBlock::iterator Next = MI.getNextNode() ?
                                       *MI.getNextNode() : Parent.end();
    restoreRegister(Parent, Next, Loc, X86::RSP, "current_rsp");

    return true;
}

/// If the BB contains a serializing instruction, the rollback happens before it
/// CLOB: spec
auto X86SpecFuzzPass::visitSerializingInstruction(MachineInstr &MI,
                                                  MachineBasicBlock &Parent) -> bool {
    LLVM_DEBUG(dbgs() << "Instrumenting a serializing instruction: " << MI);
    DebugLoc Loc = MI.getDebugLoc();
    addCallRuntimeFunction(Parent, MI, Loc, "specfuzz_rlbk_serializing");
    return true;
}

/// Inserts an additional call to specfuzz_rlbk_if_done into a long BB
/// CLOB: spec flags
auto X86SpecFuzzPass::insertAdditionalCheck(MachineInstr &MI,
                                            MachineBasicBlock &Parent,
                                            int Offset) -> bool {
    LLVM_DEBUG(dbgs() << "Adding an additional check into a long BB: " << MI);
    DebugLoc Loc = MI.getDebugLoc();

    addCallRuntimeFunction(Parent, MI, Loc, "specfuzz_rlbk_if_done");

    BuildMI(Parent, MI, Loc, TII->get(X86::SUB64mi8))
        .addReg(0).addImm(1)
        .addReg(0).addExternalSymbol("instruction_counter")
        .addReg(0).addImm(MinCheckInterval - Offset);

    return false;
}

/// A simple pass that adds calls to specfuzz_cov_trace_pc_wrapper before every
/// conditional jump. Used for measuring native coverage
auto X86SpecFuzzPass::coveragePass(MachineFunction &MF) -> bool {
    bool Modified = false;

    // We're not interested in empty functions
    if (MF.begin() == MF.end())
        return Modified;

    // Blacklist functions
    // TBD: implement proper blacklisting
    if (MF.getName().contains("asan")) {
        LLVM_DEBUG(dbgs() << "Blacklisted\n");
        return Modified;
    }

    // Iterate over all instructions
    std::vector<MachineInstr *> Conditionals;
    for (auto &MBB : MF)
        for (auto &MI : MBB)
            if (MI.isTerminator() && MI.isConditionalBranch()) {
                // A work around for an LLVM bug (or, at least, it looks like a bug)
                // If a BB uses UCOMISDrr and has two terminators, adding an instruction
                // before a terminator messes up with labels
                // Skip instrumentation in these cases
                if (MI.getPrevNode() && MI.getPrevNode()->getOpcode() == X86::UCOMISDrr &&
                    std::distance(MBB.terminators().begin(), MBB.terminators().end()) == 2) {
                    LLVM_DEBUG(dbgs() << "Skipping as a bug workaround: " << MI);
                    break;
                }
                Conditionals.push_back(&MI);
            }

    for (MachineInstr *MI : Conditionals) {
        LLVM_DEBUG(dbgs() << "Adding coverage call to " << *MI);
        BuildMI(*MI->getParent(), MI, MI->getDebugLoc(), TII->get(X86::CALLpcrel32))
            .addExternalSymbol("specfuzz_cov_trace_pc_wrapper");
        Modified = true;
    }

    return Modified;
}


//===---------------------------- Helpers --------------------------------===//

/// Splits a Machine Basic Block in two
auto X86SpecFuzzPass::splitMBBAt(MachineBasicBlock &CurMBB,
                                 MachineBasicBlock::iterator SplitAt) -> MachineBasicBlock * {
    MachineFunction &MF = *CurMBB.getParent();

    // Create the fall-through block.
    MachineBasicBlock *NewMBB = MF.CreateMachineBasicBlock(CurMBB.getBasicBlock());

    // Move all the successors of this block to the specified block.
    for (auto I = CurMBB.succ_begin(); I != CurMBB.succ_end(); ++I) {
        NewMBB->copySuccessor(&CurMBB, I);
    }

    // Add an edge from CurMBB to NewMBB for the fall-through.
    CurMBB.addSuccessor(NewMBB);

    // Insert the new block into the function
    MF.insert(std::next(MachineFunction::iterator(CurMBB)), NewMBB);

    // Transfer a part of the instructions into the new MBB
    NewMBB->splice(NewMBB->end(), &CurMBB, SplitAt, CurMBB.end());

    return NewMBB;
}

auto X86SpecFuzzPass::isSerializingInstruction(MachineInstr &MI) -> bool {
    // We should stop simulation before exiting
    if (MI.isReturn() && MI.getParent()->getParent()->getName() == "main")
        return true;

    // We don't have any way to analise inline asm. Thus, conservatively consider it serializing.
    // We ignore, though, empty inline assembly placeholders that some LLVM passes add
    if (MI.isInlineAsm() && strcmp(MI.getOperand(0).getSymbolName(), "") != 0) return true;

    // Check if it is an explicitly serializing instruction
    if (isExplicitlySerializing(MI.getOpcode())) return true;  // NOLINT

    return false;
}

auto X86SpecFuzzPass::getCallTargetType(MachineInstr &MI) -> X86SpecFuzzPass::CallTargetType {
    const std::set<StringRef> ASanWrappers = {
        "__asan_memcpy",
        "__asan_memset",
        "__asan_memmove",

        // the following function are here temporary
        "__asan_set_shadow_00",
        "__asan_set_shadow_f1",
        "__asan_set_shadow_f2",
        "__asan_set_shadow_f3",
        "__asan_set_shadow_f5",
        "__asan_set_shadow_f8",

        "__asan_frame_malloc_0",
		"__asan_stack_malloc_0",
        "__asan_stack_malloc_1",
        "__asan_stack_malloc_2",
        "__asan_stack_malloc_3",
        "__asan_stack_malloc_4",
        "__asan_stack_malloc_5",
        "__asan_stack_malloc_6",
        "__asan_stack_malloc_7",
        "__asan_stack_malloc_8",
        "__asan_stack_malloc_9",
        "__asan_stack_malloc_10",

        "__asan_stack_free_0",
        "__asan_stack_free_1",
        "__asan_stack_free_2",
        "__asan_stack_free_3",
        "__asan_stack_free_4",
        "__asan_stack_free_5",
        "__asan_stack_free_6",
        "__asan_stack_free_7",
        "__asan_stack_free_8",
        "__asan_stack_free_9",
        "__asan_stack_free_10",

        "__asan_alloca_poison",
        "__asan_poison_cxx_array_cookie",
        "__asan_poison_intra_object_redzone",
        "__asan_poison_memory_region",
        "__asan_poison_stack_memory",
        "__asan_register_elf_globals",
        "__asan_register_globals",
        "__asan_register_globals.part.13",
        "__asan_register_image_globals",

        "__asan_unpoison_intra_object_redzone",
        "__asan_unpoison_memory_region",
        "__asan_unpoison_stack_memory",
        "__asan_allocas_unpoison",
        "__asan_unregister_elf_globals",
        "__asan_unregister_globals",
        "__asan_unregister_image_globals",

        "__asan_handle_no_return",
    };

    const MachineOperand &CallTarget = MI.getOperand(0);
    StringRef TargetName;  // the default name is guaranteed to be on the list

    switch (CallTarget.getType()) {
        case MachineOperand::MO_Register:
            return IndirectTarget;
        case MachineOperand::MO_MCSymbol:
            TargetName = CallTarget.getMCSymbol()->getName();
            break;
        case MachineOperand::MO_GlobalAddress:
            TargetName = CallTarget.getGlobal()->getName();
            break;
        case MachineOperand::MO_ExternalSymbol:
            TargetName = CallTarget.getSymbolName();
            break;
        default:
            llvm_unreachable("Unexpected CallTarget type");
    }

    assert(not TargetName.empty());

    // ASan wrappers for standard functions
    if (ASanWrappers.count(TargetName) != 0) {
        return ASanWrapperTarget;
    }

    // All other ASan functions
    if (TargetName.contains("asan")) {
        return ASanTarget;
    }

    // External Calls
    if (not InstrumentedFunctions.count(TargetName)) {
        return ExternalTarget;
    }

    return InstrumentedTarget;
}

/// Counts MachineInstruction that translate into real assembly instructions
auto X86SpecFuzzPass::countRealInstructions(MachineBasicBlock &MBB) -> int {
    int count = 0;
    for (MachineInstr &I : MBB) {
        if (I.isMetaInstruction() or isFirstInFusedPair(I))
            continue;
        count++;
    }

    if (count == 0)
        return 0;

    if ((count % MinCheckInterval) == 0)
        return MinCheckInterval + 1;

    return (count % MinCheckInterval) + 1;
}

/// When we add a call to a runtime function, there is a risk that the call
/// will corrupt values on the stack. To avoid it, we usa a separate, disjoint stack
/// for the runtime functions.
///
/// The added code:
///     MOVQ %rsp, current_rsp
///     LEAQ specfuzz_rtl_frame, %rsp
///     CALL specfuzz_...
///     MOVQ current_rsp, %rsp
///
void X86SpecFuzzPass::addCallRuntimeFunction(MachineBasicBlock &MBB,
                                             MachineInstr &MI,
                                             DebugLoc &Loc,
                                             const char *FunctionName) {
    BuildMI(MBB, MI, Loc, TII->get(X86::MOV64mr))
        .addReg(0).addImm(1)
        .addReg(0).addExternalSymbol("current_rsp")
        .addReg(0)
        .addReg(X86::RSP);
    BuildMI(MBB, MI, Loc, TII->get(X86::LEA64r))
        .addReg(X86::RSP)
        .addReg(0).addImm(1)
        .addReg(0).addExternalSymbol("specfuzz_rtl_frame")
        .addReg(0);
    BuildMI(MBB, MI, Loc, TII->get(X86::CALLpcrel32))
        .addExternalSymbol(FunctionName);
    BuildMI(MBB, MI, Loc, TII->get(X86::MOV64rm))
        .addReg(X86::RSP)
        .addReg(0).addImm(1)
        .addReg(0).addExternalSymbol("current_rsp")
        .addReg(0);
}

/// Stores a register into memory
///     MOVQ %Register, Location
///
void X86SpecFuzzPass::preserveRegister(MachineBasicBlock &Parent,
                                       MachineInstr &InsertBefore,
                                       DebugLoc &DL,
                                       unsigned Register,
                                       const char *Location) {
    BuildMI(Parent, InsertBefore, DL, TII->get(X86::MOV64mr))
        .addReg(0).addImm(1)
        .addReg(0).addExternalSymbol(Location)
        .addReg(0)
        .addReg(Register);
}

void X86SpecFuzzPass::preserveRegister(MachineBasicBlock &Parent,
                                       MachineBasicBlock::iterator InsertBefore,
                                       DebugLoc &DL,
                                       unsigned Register,
                                       const char *Location) {
    BuildMI(Parent, InsertBefore, DL, TII->get(X86::MOV64mr))
        .addReg(0).addImm(1)
        .addReg(0).addExternalSymbol(Location)
        .addReg(0)
        .addReg(Register);
}

/// Loads a register from memory
///     MOVQ Location, %Register
///
void X86SpecFuzzPass::restoreRegister(MachineBasicBlock &Parent,
                                      MachineInstr &InsertBefore,
                                      DebugLoc &DL,
                                      unsigned Register,
                                      const char *Location) {
    BuildMI(Parent, InsertBefore, DL, TII->get(X86::MOV64rm), Register)
        .addReg(0).addImm(1)
        .addReg(0).addExternalSymbol(Location)
        .addReg(0);
}

void X86SpecFuzzPass::restoreRegister(MachineBasicBlock &Parent,
                                      MachineBasicBlock::iterator InsertBefore,
                                      DebugLoc &DL,
                                      unsigned Register,
                                      const char *Location) {
    BuildMI(Parent, InsertBefore, DL, TII->get(X86::MOV64rm), Register)
        .addReg(0).addImm(1)
        .addReg(0).addExternalSymbol(Location)
        .addReg(0);
}

/// Returns a complete debug location as a string, including the absolute path
auto X86SpecFuzzPass::getCompleteDebugLocation(DebugLoc &Loc) -> std::string {
    if (!Loc)
        return "";

    std::string LocName = cast<DIScope>(Loc.getScope())->getDirectory();
    LocName.append("/");
    LocName.append(cast<DIScope>(Loc.getScope())->getFilename().str());
    LocName.append(":");
    LocName.append(std::to_string(Loc.getLine()));
    LocName.append(":");
    LocName.append(std::to_string(Loc.getCol()));
    return LocName;
}

/// Converts a conditional jump into an inverted one
/// E.g., JE -> JNE
auto X86SpecFuzzPass::reverseJump(unsigned Opcode) -> unsigned {
    switch (Opcode) {
        case X86::JO_1 :
            return X86::JNO_1;
        case X86::JNO_1:
            return X86::JO_1;
        case X86::JS_1 :
            return X86::JNS_1;
        case X86::JNS_1:
            return X86::JS_1;
        case X86::JE_1 :
            return X86::JNE_1;
        case X86::JNE_1:
            return X86::JE_1;
        case X86::JB_1 :
            return X86::JAE_1;
        case X86::JAE_1:
            return X86::JB_1;
        case X86::JBE_1:
            return X86::JA_1;
        case X86::JA_1 :
            return X86::JBE_1;
        case X86::JL_1 :
            return X86::JGE_1;
        case X86::JGE_1:
            return X86::JL_1;
        case X86::JLE_1:
            return X86::JG_1;
        case X86::JG_1 :
            return X86::JLE_1;
        case X86::JP_1 :
            return X86::JNP_1;
        case X86::JNP_1:
            return X86::JP_1;
        case X86::JO_2 :
            return X86::JNO_2;
        case X86::JNO_2:
            return X86::JO_2;
        case X86::JS_2 :
            return X86::JNS_2;
        case X86::JNS_2:
            return X86::JS_2;
        case X86::JE_2 :
            return X86::JNE_2;
        case X86::JNE_2:
            return X86::JE_2;
        case X86::JB_2 :
            return X86::JAE_2;
        case X86::JAE_2:
            return X86::JB_2;
        case X86::JBE_2:
            return X86::JA_2;
        case X86::JA_2 :
            return X86::JBE_2;
        case X86::JL_2 :
            return X86::JGE_2;
        case X86::JGE_2:
            return X86::JL_2;
        case X86::JLE_2:
            return X86::JG_2;
        case X86::JG_2 :
            return X86::JLE_2;
        case X86::JP_2 :
            return X86::JNP_2;
        case X86::JNP_2:
            return X86::JP_2;
        case X86::JO_4 :
            return X86::JNO_4;
        case X86::JNO_4:
            return X86::JO_4;
        case X86::JS_4 :
            return X86::JNS_4;
        case X86::JNS_4:
            return X86::JS_4;
        case X86::JE_4 :
            return X86::JNE_4;
        case X86::JNE_4:
            return X86::JE_4;
        case X86::JB_4 :
            return X86::JAE_4;
        case X86::JAE_4:
            return X86::JB_4;
        case X86::JBE_4:
            return X86::JA_4;
        case X86::JA_4 :
            return X86::JBE_4;
        case X86::JL_4 :
            return X86::JGE_4;
        case X86::JGE_4:
            return X86::JL_4;
        case X86::JLE_4:
            return X86::JG_4;
        case X86::JG_4 :
            return X86::JLE_4;
        case X86::JP_4 :
            return X86::JNP_4;
        case X86::JNP_4:
            return X86::JP_4;
        case X86::JCXZ:
        case X86::JECXZ:
            errs() << TII->getName(Opcode) << "\n";
            llvm_unreachable("The jump does not have a reversed version.");
        default:
            errs() << TII->getName(Opcode) << "\n";
            llvm_unreachable("The jump is not in the list of reversible jumps.");
    }
}

/// Some pairs of instructions are prone to macro-fusion (see Intel
/// Optimization Manual, Table "Macro-Fusible Instructions" for details)
/// To account for this effect, we ignore the first instruction in a pair
/// when counting instructions
///
auto X86SpecFuzzPass::isFirstInFusedPair(MachineInstr &MI) -> bool {
    if (not MI.getNextNode() or not MI.getNextNode()->isConditionalBranch())
        return false;

    // For simplicity, we conservatively assume that all of the following
    // instructions could be merged with conditional jumps
    switch (MI.getOpcode()) {
        case X86::TEST8i8:
        case X86::TEST16i16:
        case X86::TEST16mi:
        case X86::TEST16mr:
        case X86::TEST16ri:
        case X86::TEST16rr:
        case X86::TEST32i32:
        case X86::TEST32mi:
        case X86::TEST32mr:
        case X86::TEST32ri:
        case X86::TEST32rr:
        case X86::TEST64i32:
        case X86::TEST64mi32:
        case X86::TEST64mr:
        case X86::TEST64ri32:
        case X86::TEST64rr:
        case X86::TEST8mi:
        case X86::TEST8mr:
        case X86::TEST8ri:
        case X86::TEST8rr:
        case X86::AND16i16:
        case X86::AND16mi:
        case X86::AND16mi8:
        case X86::AND16mr:
        case X86::AND16ri:
        case X86::AND16ri8:
        case X86::AND16rm:
        case X86::AND16rr:
        case X86::AND16rr_REV:
        case X86::AND32i32:
        case X86::AND32mi:
        case X86::AND32mi8:
        case X86::AND32mr:
        case X86::AND32ri:
        case X86::AND32ri8:
        case X86::AND32rm:
        case X86::AND32rr:
        case X86::AND32rr_REV:
        case X86::AND64i32:
        case X86::AND64mi32:
        case X86::AND64mi8:
        case X86::AND64mr:
        case X86::AND64ri32:
        case X86::AND64ri8:
        case X86::AND64rm:
        case X86::AND64rr:
        case X86::AND64rr_REV:
        case X86::AND8i8:
        case X86::AND8mi:
        case X86::AND8mi8:
        case X86::AND8mr:
        case X86::AND8ri:
        case X86::AND8ri8:
        case X86::AND8rm:
        case X86::AND8rr:
        case X86::CMP16i16:
        case X86::CMP16mi:
        case X86::CMP16mi8:
        case X86::CMP16mr:
        case X86::CMP16ri:
        case X86::CMP16ri8:
        case X86::CMP16rm:
        case X86::CMP16rr:
        case X86::CMP16rr_REV:
        case X86::CMP32i32:
        case X86::CMP32mi:
        case X86::CMP32mi8:
        case X86::CMP32mr:
        case X86::CMP32ri:
        case X86::CMP32ri8:
        case X86::CMP32rm:
        case X86::CMP32rr:
        case X86::CMP32rr_REV:
        case X86::CMP64i32:
        case X86::CMP64mi32:
        case X86::CMP64mi8:
        case X86::CMP64mr:
        case X86::CMP64ri32:
        case X86::CMP64ri8:
        case X86::CMP64rm:
        case X86::CMP64rr:
        case X86::CMP64rr_REV:
        case X86::CMP8i8:
        case X86::CMP8mi:
        case X86::CMP8mi8:
        case X86::CMP8mr:
        case X86::CMP8ri:
        case X86::CMP8ri8:
        case X86::CMP8rm:
        case X86::CMP8rr:
        case X86::CMP8rr_REV:
        case X86::ADD16i16:
        case X86::ADD16mi:
        case X86::ADD16mi8:
        case X86::ADD16mr:
        case X86::ADD16ri:
        case X86::ADD16ri8:
        case X86::ADD16ri8_DB:
        case X86::ADD16ri_DB:
        case X86::ADD16rm:
        case X86::ADD16rr:
        case X86::ADD16rr_DB:
        case X86::ADD16rr_REV:
        case X86::ADD32i32:
        case X86::ADD32mi:
        case X86::ADD32mi8:
        case X86::ADD32mr:
        case X86::ADD32ri:
        case X86::ADD32ri8:
        case X86::ADD32ri8_DB:
        case X86::ADD32ri_DB:
        case X86::ADD32rm:
        case X86::ADD32rr:
        case X86::ADD32rr_DB:
        case X86::ADD32rr_REV:
        case X86::ADD64i32:
        case X86::ADD64mi32:
        case X86::ADD64mi8:
        case X86::ADD64mr:
        case X86::ADD64ri32:
        case X86::ADD64ri32_DB:
        case X86::ADD64ri8:
        case X86::ADD64ri8_DB:
        case X86::ADD64rm:
        case X86::ADD64rr:
        case X86::ADD64rr_DB:
        case X86::ADD64rr_REV:
        case X86::ADD8i8:
        case X86::ADD8mi:
        case X86::ADD8mi8:
        case X86::ADD8mr:
        case X86::ADD8ri:
        case X86::ADD8ri8:
        case X86::ADD8rm:
        case X86::ADD8rr:
        case X86::ADD8rr_REV:
        case X86::SUB16i16:
        case X86::SUB16mi:
        case X86::SUB16mi8:
        case X86::SUB16mr:
        case X86::SUB16ri:
        case X86::SUB16ri8:
        case X86::SUB16rm:
        case X86::SUB16rr:
        case X86::SUB16rr_REV:
        case X86::SUB32i32:
        case X86::SUB32mi:
        case X86::SUB32mi8:
        case X86::SUB32mr:
        case X86::SUB32ri:
        case X86::SUB32ri8:
        case X86::SUB32rm:
        case X86::SUB32rr:
        case X86::SUB32rr_REV:
        case X86::SUB64i32:
        case X86::SUB64mi32:
        case X86::SUB64mi8:
        case X86::SUB64mr:
        case X86::SUB64ri32:
        case X86::SUB64ri8:
        case X86::SUB64rm:
        case X86::SUB64rr:
        case X86::SUB64rr_REV:
        case X86::SUB8i8:
        case X86::SUB8mi:
        case X86::SUB8mi8:
        case X86::SUB8mr:
        case X86::SUB8ri:
        case X86::SUB8ri8:
        case X86::SUB8rm:
        case X86::SUB8rr:
        case X86::SUB8rr_REV:
        case X86::INC16m:
        case X86::INC16r:
        case X86::INC16r_alt:
        case X86::INC32m:
        case X86::INC32r:
        case X86::INC32r_alt:
        case X86::INC64m:
        case X86::INC64r:
        case X86::INC8m:
        case X86::INC8r:
        case X86::DEC16m:
        case X86::DEC16r:
        case X86::DEC16r_alt:
        case X86::DEC32m:
        case X86::DEC32r:
        case X86::DEC32r_alt:
        case X86::DEC64m:
        case X86::DEC64r:
        case X86::DEC8m:
        case X86::DEC8r:
            return true;
    }

    return false;
}

auto X86SpecFuzzPass::isAcquireOrRelease(unsigned Opcode) -> bool {
    switch (Opcode) {
        case X86::ACQUIRE_MOV8rm:
        case X86::ACQUIRE_MOV16rm:
        case X86::ACQUIRE_MOV32rm:
        case X86::ACQUIRE_MOV64rm:
        case X86::RELEASE_MOV8mr:
        case X86::RELEASE_MOV16mr:
        case X86::RELEASE_MOV32mr:
        case X86::RELEASE_MOV64mr:
        case X86::RELEASE_MOV8mi:
        case X86::RELEASE_MOV16mi:
        case X86::RELEASE_MOV32mi:
        case X86::RELEASE_MOV64mi32:
        case X86::RELEASE_ADD8mi:
        case X86::RELEASE_ADD8mr:
        case X86::RELEASE_ADD32mi:
        case X86::RELEASE_ADD32mr:
        case X86::RELEASE_ADD64mi32:
        case X86::RELEASE_ADD64mr:
        case X86::RELEASE_AND8mi:
        case X86::RELEASE_AND8mr:
        case X86::RELEASE_AND32mi:
        case X86::RELEASE_AND32mr:
        case X86::RELEASE_AND64mi32:
        case X86::RELEASE_AND64mr:
        case X86::RELEASE_OR8mi:
        case X86::RELEASE_OR8mr:
        case X86::RELEASE_OR32mi:
        case X86::RELEASE_OR32mr:
        case X86::RELEASE_OR64mi32:
        case X86::RELEASE_OR64mr:
        case X86::RELEASE_XOR8mi:
        case X86::RELEASE_XOR8mr:
        case X86::RELEASE_XOR32mi:
        case X86::RELEASE_XOR32mr:
        case X86::RELEASE_XOR64mi32:
        case X86::RELEASE_XOR64mr:
        case X86::RELEASE_INC8m:
        case X86::RELEASE_INC16m:
        case X86::RELEASE_INC32m:
        case X86::RELEASE_INC64m:
        case X86::RELEASE_DEC8m:
        case X86::RELEASE_DEC16m:
        case X86::RELEASE_DEC32m:
        case X86::RELEASE_DEC64m:
            return true;
        default:
            return false;
    }
}

auto X86SpecFuzzPass::isExplicitlySerializing(unsigned Opcode) -> bool {
    switch (Opcode) {
        case X86::LFENCE:
        case X86::MFENCE:
        case X86::CPUID:
        case X86::TRAP:
            return true;
        default:
            return false;
    }
}

auto X86SpecFuzzPass::isPush(unsigned Opcode) -> int {
    switch (Opcode) {
        case X86::PUSH16i8:
        case X86::PUSH16r:
        case X86::PUSH16rmm:
        case X86::PUSH16rmr:
        case X86::PUSHi16:
        case X86::PUSHA16:
        case X86::PUSHCS16:
        case X86::PUSHDS16:
        case X86::PUSHES16:
        case X86::PUSHSS16:
        case X86::PUSHF16:
        case X86::PUSHFS16:
        case X86::PUSHGS16:
            return 2;
        case X86::PUSH32i8:
        case X86::PUSH32r:
        case X86::PUSH32rmm:
        case X86::PUSH32rmr:
        case X86::PUSHi32:
        case X86::PUSHA32:
        case X86::PUSHCS32:
        case X86::PUSHDS32:
        case X86::PUSHES32:
        case X86::PUSHSS32:
        case X86::PUSHF32:
        case X86::PUSHFS32:
        case X86::PUSHGS32:
            return 4;
        case X86::PUSH64i8:
        case X86::PUSH64i32:
        case X86::PUSH64r:
        case X86::PUSH64rmm:
        case X86::PUSH64rmr:
        case X86::PUSHF64:
        case X86::PUSHFS64:
        case X86::PUSHGS64:
            return 8;
        default:
            return 0;
    }
}

void X86SpecFuzzPass::readIntoList(std::string &File, std::set<std::string> *List) {
    std::string line;
    std::ifstream inFile(File, std::ios_base::in);
    while (getline(inFile, line)) {
        if (line.empty()) continue;
        List->insert(line);
    }
}

INITIALIZE_PASS_BEGIN(X86SpecFuzzPass, DEBUG_TYPE, PASS_DESCRIPTION, false, false)
INITIALIZE_PASS_END(X86SpecFuzzPass, DEBUG_TYPE, PASS_DESCRIPTION, false, false)

auto llvm::createX86SpecFuzzPass() -> FunctionPass * {
    return new X86SpecFuzzPass();
}
