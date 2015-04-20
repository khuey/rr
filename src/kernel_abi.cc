/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#define DEBUGTAG "KernelABI"

#include "kernel_abi.h"

#include <stdlib.h>

#include "task.h"

using namespace std;

static const uint8_t int80_insn[] = { 0xcd, 0x80 };
static const uint8_t sysenter_insn[] = { 0x0f, 0x34 };
static const uint8_t syscall_insn[] = { 0x0f, 0x05 };
static const uint8_t arm_syscall_insn[] = { 0x00, 0x00, 0x00, 0xef };
static const uint8_t thumb_syscall_insn[] = { 0x00, 0xdf };

namespace rr {

bool is_at_syscall_instruction(Task* t, remote_code_ptr ptr) {
  vector<uint8_t> code = t->read_mem(ptr.to_data_ptr<uint8_t>(), 2);
  switch (t->arch()) {
    case x86:
      return memcmp(code.data(), int80_insn, sizeof(int80_insn)) == 0 ||
             memcmp(code.data(), sysenter_insn, sizeof(sysenter_insn)) == 0;
    case x86_64:
      return memcmp(code.data(), syscall_insn, sizeof(syscall_insn)) == 0 ||
             memcmp(code.data(), sysenter_insn, sizeof(sysenter_insn)) == 0;
    case ARM:{
      if (ptr.register_value() & 0x1) {
        return memcmp(code.data(), thumb_syscall_insn, sizeof(thumb_syscall_insn)) == 0;
      } else {
        vector<uint8_t> code = t->read_mem(ptr.to_data_ptr<uint8_t>(), 4);
        return memcmp(code.data(), arm_syscall_insn, sizeof(arm_syscall_insn)) == 0;
      }
    }
    default:
      assert(0 && "Need to define syscall instructions");
      return false;
  }
}

vector<uint8_t> syscall_instruction(SupportedArch arch) {
  switch (arch) {
    case x86:
      return vector<uint8_t>(int80_insn, int80_insn + sizeof(int80_insn));
    case x86_64:
      return vector<uint8_t>(syscall_insn, syscall_insn + sizeof(syscall_insn));
    case ARM:
      return vector<uint8_t>(arm_syscall_insn, arm_syscall_insn + sizeof(arm_syscall_insn));
    default:
      assert(0 && "Need to define syscall instruction");
      return vector<uint8_t>();
  }
}

ssize_t syscall_instruction_length(SupportedArch arch) {
  switch (arch) {
    case x86:
    case x86_64:
      return 2;
    case ARM:
      return 4;
    default:
      assert(0 && "Need to define syscall instruction length");
      return 0;
  }
}
}

#include "log.h"
#include "task.h"
#include "util.h"

namespace rr {

static uint32_t read_pc(Task* t)
{
  remote_ptr<uint32_t> ptr = t->regs().ip().to_data_ptr<uint32_t>();

  return ptr.as_int() + ((t->current_instruction_set() == ARM_IA) ? 8 : 4);
}

static bool is_condition_true(uint8_t condition_block, uint32_t flags)
{
  assert((condition_block & 0xF0) == 0); // Invalid condition block.

  const uint32_t FLAG_N = 0x80000000;
  const uint32_t FLAG_Z = 0x40000000;
  const uint32_t FLAG_C = 0x20000000;
  const uint32_t FLAG_V = 0x10000000;

  switch (condition_block) {
  case 0x0: // EQ
    LOG(debug) << "evaluating conditon eq";
    return !!(flags & FLAG_Z);
  case 0x1: // NE
    LOG(debug) << "evaluating condition ne";
    return !(flags & FLAG_Z);
  case 0x2: // CS
    return !!(flags & FLAG_C);
  case 0x3: // CC
    return !(flags & FLAG_C);
  case 0x4: // MI
    return !!(flags & FLAG_N);
  case 0x5: // PL
    return !(flags & FLAG_N);
  case 0x6: // VS
    return !!(flags & FLAG_V);
  case 0x7: // VC
    return !(flags & FLAG_V);
  case 0x8: // HI
    return (flags & (FLAG_C | FLAG_Z)) == FLAG_C;
  case 0x9: // LS
    return (flags & (FLAG_C | FLAG_Z)) != FLAG_C;
  case 0xA: // GE
    return !!(flags & FLAG_N) == !!(flags & FLAG_V);
  case 0xB: // LT
    LOG(debug) << "evaluating condition lt";
    LOG(debug) << "flags & FLAG_N: " << (flags & FLAG_N);
    LOG(debug) << "flags & FLAG_V: " << (flags & FLAG_V);
    return !!(flags & FLAG_N) != !!(flags & FLAG_V);
  case 0xC: // GT
    return !(flags & FLAG_Z) && (!!(flags & FLAG_N) == !!(flags & FLAG_V));
  case 0xD: // LE
    return !!(flags & FLAG_Z) || (!!(flags & FLAG_N) != !!(flags & FLAG_V));
  case 0xE: // AL
  case 0xF: // Unconditional instruction
    return true;
  default:
    assert(false);
  }
}

static bool thumb_insn_is_two_bytes(uint16_t insn) {
  // All of the Thumb2 instructions have bits 13-15 set and at least one of bits
  // 11 and 12 set.
  const uint16_t THUMB2_ALL_REQUIRED_MASK = 0xE000;
  const uint16_t THUMB2_ONE_REQUIRED_MASK = 0x1800;
  if ((insn & THUMB2_ALL_REQUIRED_MASK) != THUMB2_ALL_REQUIRED_MASK) {
    LOG(debug) << "Determined that " << insn << " is two bytes";
    return true;
  }

  if (!(insn & THUMB2_ONE_REQUIRED_MASK)) {
    LOG(debug) << "determined that " << insn << " is two bytes";
    return true;
  }

  LOG(debug) << "Determined that " << insn << "is four bytes";
  return false;
}

static uint8_t advance_itstate(uint8_t itstate) {
  const uint8_t ITSTATE_CONDITION_MASK = 0xE0;
  const uint8_t ITSTATE_ITERATION_MASK = 0x1F;
  uint8_t new_itstate = (itstate & ITSTATE_CONDITION_MASK) |
                         ((itstate << 1) & ITSTATE_ITERATION_MASK);

  if (!(new_itstate & 0x0F))
    return 0;

  return new_itstate;
}

static uint32_t shifted_register(Task* t, uint32_t current_insn, bool carry)
{
  const uint32_t SOURCE_REGISTER_MASK = 0x0000000F;
  uint8_t regno = current_insn & SOURCE_REGISTER_MASK;

  const uint32_t HAS_SHIFT_REGISTER_MASK = 0x00000010;
  uint32_t shift;
  if (current_insn & HAS_SHIFT_REGISTER_MASK) {
    // The shift value is in a register.
    const uint32_t SHIFT_REGISTER_MASK = 0x00000F00;
    uint8_t shift_regno = (current_insn & SHIFT_REGISTER_MASK) >> 8;
    shift = (shift_regno == 15) ? read_pc(t) 
                                : (t->regs().by_number(shift_regno) & 0xFF);
  } else {
    // The shift value is an immediate.
    const uint32_t SHIFT_IMMEDIATE_MASK = 0x00000F80;
    shift = (current_insn & SHIFT_IMMEDIATE_MASK) >> 7;
  }

  uint32_t result = (regno == 15) ? (read_pc(t) + (!!(current_insn & HAS_SHIFT_REGISTER_MASK) ? 4 : 0)) :
    t->regs().by_number(regno);

  LOG(debug) << "shifted register result before shift: " << result;

  switch ((current_insn & 0x00000060) >> 5) {
  case 0x0: // LSL
    return result << shift; 
  case 0x1: // LSR
    return result >> shift;
  case 0x2: // ASR
    shift = std::max<uint32_t>(shift, 31);
    if (result & 0x80000000) {
      // Signed.
      return ~((~result) >> shift);
    } else {
      // Unsigned.
      return result >> shift;
    }
  case 0x3: // ROR/RRX
    shift &= 31;
    if (shift) {
      return (result >> shift) | (result << (32 - shift));
    } else {
      return (result >> 1) | (carry ? 0x80000000 : 0);
    }
  default:
    assert(false);
  }
}

static uint32_t sign_extended_offset(uint32_t value, uint8_t first_bit, uint8_t last_bit)
{
  uint32_t mask = (1 << ((last_bit - first_bit) + 1)) - 1;
  bool high_bit = !!((value >> last_bit) & 1);

  uint32_t extended_value = ((value >> first_bit) & mask);
  if (high_bit) {
    extended_value |= ~mask;
  }
  return extended_value;
}

int ARMArch::emulate_single_stepping(int how, Task* t) {
  LOG(debug) << "Emulating single stepping";

  remote_code_ptr this_pc = t->regs().ip();
  remote_code_ptr next_pc;

  if (t->current_instruction_set() == ARM_IA) {
    // ARM
    remote_ptr<uint32_t> this_pc_data = this_pc.to_data_ptr<uint32_t>();
    uint32_t current_insn = t->read_mem(this_pc_data);
    next_pc = this_pc + 4;

    LOG(debug) << "ARM instruction set. this_pc: " << this_pc << " default next_pc: " << next_pc << " current_insn: " << HEX(current_insn);

    // Determine if the current instruction will change the pc to something
    // other than next_pc.

    const uint32_t CONDITIONAL_BLOCK_MASK = 0xF0000000;
    const uint32_t UNCONDITIONAL_INSTRUCTION = 0xF0000000;
    const uint32_t condition_block = (current_insn & CONDITIONAL_BLOCK_MASK);
    if (condition_block == UNCONDITIONAL_INSTRUCTION) {
      // Unconditional instruction.  Only BLX can change the pc.
      const uint32_t UNCONDITIONAL_BLX_MASK = 0x0E000000;
      const uint32_t UNCONDITIONAL_BLX_VALUE = 0x0A000000;
      if ((current_insn & UNCONDITIONAL_BLX_MASK) == UNCONDITIONAL_BLX_VALUE) {
        // BLX.  This means next_pc will be a thumb instruction.  BLX encodes a
        // 24 bit PC relative address.
        uint32_t offset = current_insn & 0x00FFFFFF;
        // XXXkhuey Sign extend with bit 24.
        assert(false);
        next_pc = this_pc + offset;
      }
    } else if (is_condition_true(condition_block >> 28, t->regs().flags())) {
      // Conditional instruction.  If the condition is false we will simply
      // advance the pc, so we don't need to do any work.

      // Switch on instruction type.  Most don't require handling.
      switch ((current_insn & 0x0F000000) >> 24) {
      case 0x0:
      case 0x1:
      case 0x2:
      case 0x3: { // Various instructions
        // The destination register is always bits 12-15 of an instruction,
        // and the pc is register 15.  If we're not writing the result to the
        // pc, we don't have to do anything.
        const uint32_t PC_DEST_REGISTER_MASK = 0x0000F000;
        if ((current_insn & PC_DEST_REGISTER_MASK) == PC_DEST_REGISTER_MASK) {
          // If we are writing to the pc, we have to decode the instruction to
          // calculate what it will do to the pc.

          // BX or BLX?
          const uint32_t BL_BLX_INSTRUCTION_MASK = 0x0FFFFFF0;
          const uint32_t BL_INSTRUCTION_VALUE  = 0x012FFF10;
          const uint32_t BLX_INSTRUCTION_VALUE = 0x012FFF30;
          if ((current_insn & BL_BLX_INSTRUCTION_MASK) == BL_INSTRUCTION_VALUE ||
              (current_insn & BL_BLX_INSTRUCTION_MASK) == BLX_INSTRUCTION_VALUE) {
            const uint32_t BL_BLX_SOURCE_REGISTER_MASK = 0x0000000F;
            int reg_no = current_insn & BL_BLX_SOURCE_REGISTER_MASK;
            next_pc = (reg_no == 15) ? this_pc + 2 : t->regs().by_number(reg_no);
            break;
          }

          const uint32_t SOURCE_REGISTER_MASK = 0x000F0000;
          uint8_t reg_no = (current_insn & SOURCE_REGISTER_MASK) >> 16;
          bool carry = !!(t->regs().flags() & 0x20000000);
          uint32_t thing1 = (reg_no == 15) ? read_pc(t) : t->regs().by_number(reg_no);
          uint32_t thing2;
          if (current_insn & 0x02000000) {
            uint32_t immediate = current_insn & 0x000000FF;
            uint32_t shift = 2 * ((current_insn & 0x00000F00) >> 8);
            thing2 = ((immediate >> shift) | (immediate << (32 - shift))) & 0xFFFFFFFF;
          } else {
            thing2 = shifted_register(t, current_insn, carry);
          }

          switch ((current_insn & 0x01E00000) >> 21) {
          case 0x0: // AND
            next_pc = thing1 & thing2;
            break;
          case 0x1: // EOR
            next_pc = thing1 ^ thing2;
            break;
          case 0x2: // SUB
            next_pc = thing1 - thing2;
            break;
          case 0x3: // RSB
            next_pc = thing2 - thing1;
            break;
          case 0x4: // ADD
            LOG(debug) << "Thing 1 " << HEX(thing1) << " Thing2 " << HEX(thing2);
            next_pc = thing1 + thing2;
            break;
          case 0x5: // ADC
            next_pc = thing1 + thing2 + carry ? 1 : 0;
            break;
          case 0x6: // SBC
            next_pc = thing1 - thing2 + carry ? 1 : 0;
            break;
          case 0x7: // RSC
            next_pc = thing2 - thing1 + carry ? 1 : 0;
            break;
          case 0x8: // TST
          case 0x9: // TEQ
          case 0xA: // CMP
          case 0xB: // CMN
            // These don't touch the pc.
            break;
          case 0xC: // ORR
            next_pc = thing1 | thing2;
            break;
          case 0xD: // MOV
            next_pc = thing2;
            break;
          case 0xE: // BIC
            next_pc = thing1 & ~thing2;
            break;
          case 0xF: // MVN
            next_pc = ~thing2;
            break;
          }
        }
        break;
      }
      case 0x4:
      case 0x5:
      case 0x6:
      case 0x7: { // Stores and loads
        // A load could change the pc.  Check that.
        const uint32_t LOAD_AFFECTING_PC_MASK = 0x00100000 | // Mask for loads
          0x0000F000; // Mask for pc destination register
        if ((current_insn & LOAD_AFFECTING_PC_MASK) == LOAD_AFFECTING_PC_MASK) {
          // This is a load that touches the pc.
          // Get the base register value.  The base register is stored in bits
          // 16-19.  If the base register is also the pc
          const uint32_t SOURCE_REGISTER_MASK = 0x000F0000;
          uint8_t regno = (current_insn & SOURCE_REGISTER_MASK) >> 16;
          remote_ptr<uint32_t> br = (regno == 15) ? read_pc(t) : t->regs().by_number(regno);

          if (current_insn & 0x01000000) {
            uint32_t offset;
            if (current_insn & 0x02000000) {
              // Shifted register.
              bool carry = !!(t->regs().flags() & 0x20000000);
              offset = shifted_register(t, current_insn, carry);
            } else {
              // immediate
              offset = current_insn & 0x00000FFF;
            }

            assert(offset % 4 == 0);

            if (current_insn & 0x00800000) {
              br += offset / 4;
            } else {
              br -= offset / 4;
            }
          }

          next_pc = t->read_mem(br);
        }
        break;
      }      
      case 0x8: // Multiple store/load
      case 0x9: {
        // A load could change the pc. Check that.
        const uint32_t MULTIPLE_LOAD_AFFECTING_PC_MASK = 0x00100000 | // Mask for loads
          0x00008000; // Mask for pc destination register.
        if ((current_insn & MULTIPLE_LOAD_AFFECTING_PC_MASK) == MULTIPLE_LOAD_AFFECTING_PC_MASK) {
          // This is load multiple that touches the pc.
          // Get the base register value.  The base register is stored in bits
          // 16-19.
          const uint32_t SOURCE_REGISTER_MASK = 0x000F0000;
          uint8_t regno = (current_insn & SOURCE_REGISTER_MASK) >> 16;
          remote_ptr<uint32_t> br = (regno == 15) ? read_pc(t) : t->regs().by_number(regno);

          // Bit 24 tells wether we do math before or after the load.
          const uint32_t MATH_BEFORE_LOAD_MASK = 0x01000000;
          bool before = !!(current_insn & MATH_BEFORE_LOAD_MASK);

          // Bit 23 tells whether we're going up or down.
          const uint32_t INCREMENT_MASK = 0x00800000;
          if (current_insn & INCREMENT_MASK) {
            // Up.  We need to count how many registers are being transferred
            // and determine our offset.
            uint8_t count = __builtin_popcount(current_insn & 0x00007F00);
            // And add 1 position if we're incrementing first.
            if (before) {
              count++;
            }
            br += count;
          } else {
            // Down.  This is actually pretty easy, because it means we're
            // first.  We only need to check before/after.
            if (before) {
              br--;
            }
          }

          next_pc = t->read_mem(br);
        }
        break;
      }
      case 0xA: // B
      case 0xB: { // BL
        // There's a 24 bit immediate encoded in the instruction that gives us
        // the offset.
        const uint32_t offset = current_insn & 0x00FFFFFF;
        next_pc = this_pc + 2 + sign_extended_offset(offset, 0, 21);
        break;
      }
      case 0xC: // STC/LDC
      case 0xD: // MCRR/MRRC
      case 0xE: // MCR/MRC/CDP
      case 0xF: // SWI
        // None of these instructions can change the pc (except SWI, but we'll
        // end up back here after the syscall).
        break;
      }
    }
  } else {
    // Thumb
    remote_ptr<uint16_t> this_pc_data = this_pc.to_data_ptr<uint16_t>();
    uint16_t current_insn = t->read_mem(this_pc_data);

    LOG(debug) << "Instruction at " << this_pc << " is " << HEX(current_insn);

    // Thumb instructions do not have the 4 bit condition codes that normal ARM
    // instructions have.  Instead they have an If-Then-Else (IT) instruction
    // that affects as many as 4 following instructions (called the IT block).
    // The state for the this is stored in the CPSR.  What's really fun is that
    // IT blocks can skip over breakpoints, so we need to calculate the next
    // enabled instruction in the block.  The ITSTATE is annoyingly split
    // across the CPSR, so let's reconstruct it.
    const uint32_t cpsr = t->regs().flags();
    uint8_t itstate = ((cpsr >> 8) & 0xFC) | ((cpsr >> 25) & 0x3);

    if ((current_insn & 0xFF00) == 0xBF00 && !!(current_insn & 0x000F)) {
      // The current instruction is an IT.
      assert(!itstate); // ARM disallows this.
      LOG(debug) << "On IT instruction, handling";
      itstate = current_insn & 0x00FF;
    }

    // Advance to the first executed instruction in the IT block, or to the
    // instruction immediately after the IT block.
    // NB: Instructions inside an IT block can cause the flags to change, which
    // can change whether or not subsequent instructions with the same condition
    // execute.  But an instruction that doesn't execute can't change flags, so
    // we can fast forward to the first executed instruction without worrying
    // about this yet.
    while (itstate != 0 && !is_condition_true(itstate >> 4, t->regs().flags())) {
      this_pc += thumb_insn_is_two_bytes(current_insn) ? 2 : 4;
      this_pc_data = this_pc.to_data_ptr<uint16_t>();
      current_insn = t->read_mem(this_pc_data);
      itstate = advance_itstate(itstate);
      LOG(debug) << "Skipping unexecuted IT block instruction, advanced to " << this_pc;
    }

    next_pc = this_pc + 2;
    LOG(debug) << "Thumb instruction set. this_pc: " << this_pc << " default next_pc: " << next_pc;

    // Now we're at an instruction that will execute.  But there's a problem.
    // If we're still in an IT block this instruction could change the flags, so
    // we can't determine what the *next* instruction in the IT block to execute
    // will be (well, short of implementing half of an ARM emulator here).  This
    // is not a problem for the final instruction in an IT block though, so let
    // it fall through (and in fact it must, because it could be something
    // interesting like a branch).
    if (itstate && (itstate & 0x0F) != 0x08) {
      // We're still in the IT block.  We know that current_insn is
      // architecturally forbidden to branch.  So let's set a breakpoint on the
      // next instruction in the IT block to match the condition *and* the next
      // instruction to not match.  One might be outside the IT block, but it
      // doesn't matter.
      this_pc += thumb_insn_is_two_bytes(current_insn) ? 2 : 4;
      itstate = advance_itstate(itstate);

      LOG(debug) << "Still in IT block, setting second breakpoint at pc: " << this_pc;

      // break
      t->vm()->add_breakpoint(this_pc, TRAP_STEPI_INTERNAL_EMULATION);

      uint8_t negated_condition_block = (itstate >> 4) & 1;
      // Skip anything and everything with the same condition.
      do {
        remote_ptr<uint16_t> next_pc_data = next_pc.to_data_ptr<uint16_t>();
        current_insn = t->read_mem(next_pc_data);
        next_pc += thumb_insn_is_two_bytes(current_insn) ? 2 : 4;
        itstate = advance_itstate(itstate);
      } while(itstate != 0 && ((itstate >> 4) & 1) == negated_condition_block);

      // Now next_pc is the first instruction with the negated condition, or the
      // first instruction outside the IT block.
    } else if (!thumb_insn_is_two_bytes(current_insn)) {
      // 32 bit Thumb2 instruction.
      uint16_t current_insn_2 = t->read_mem(next_pc.to_data_ptr<uint16_t>());
      next_pc += 2;
      LOG(debug) << "32 bit Thumb2 instruction, second half: " << HEX(current_insn_2);

      if ((current_insn & 0xF800) == 0xF000 && (current_insn_2 & 0x8000) == 0x8000) {
        if (!!(current_insn_2 & 0x1000) || (current_insn_2 & 0xD001) == 0xC000) {
          // B, BL, BLX.
          LOG(debug) << "Thumb2 unconditional jump. Insn1: " << HEX(current_insn) << " Insn2: " << HEX(current_insn_2);

          // Reconstruct the immediate value
          uint32_t offset = 0;
          // ARM is annoying ...
          offset = current_insn_2 & 0x07FF ; // imm11
          offset += (current_insn & 0x07FF) << 11; // S + imm10
          offset = sign_extended_offset(offset, 0, 21);
          offset ^= !(current_insn_2 & 0x2000) << 23 | // J1
                    !(current_insn_2 & 0x0800) << 22; // J2
          next_pc = this_pc + 2 * (2 + offset);

          LOG(debug) << "Jump offset calculated as " << HEX(offset);

          if (!(current_insn_2 & 0x1000)) {
            // BLX, we're transitioning to ARM state.
            next_pc = next_pc.register_value() & 0xFFFFFFFC;
          }
        } else if (current_insn == 0xF3DE && (current_insn_2 & 0xFF00) == 0x3F00) {
          // SUBS PC, LR, immediate
          assert(false);
        } else if ((current_insn_2 & 0xD000) == 0x8000 && (current_insn & 0x0380) != 0x0380) {
          // Conditional branch
          uint8_t condition_block = (current_insn & 0x03C0) >> 6;
          LOG(debug) << "Handling conditional branch w/cond: " << HEX(condition_block) << "\n         flags " << HEX(t->regs().flags());
          if (is_condition_true(condition_block, t->regs().flags())) {
            // Reconstruct the immediate value
            uint32_t offset = 0;
            // ARM is annoying ...
            offset = current_insn_2 & 0x07FF ; // imm11
            offset += (current_insn & 0x003F) << 11; // imm6
            offset += (current_insn_2 & 0x2000) << 4; // j1
            offset += (current_insn_2 & 0x0800) << 7; // j2
            offset += (current_insn & 0x0400) << 9; // sign
            next_pc = this_pc + 2 * (2 + sign_extended_offset(offset, 0, 19));
          }
        }
      } else if ((current_insn & 0xFE50) == 0xE810) {
        // Load multiple or RFE.
        LOG(debug) << "Load multiple or RFE";
        uint8_t base_register = current_insn & 0x000F;
        remote_ptr<uint32_t> base = t->regs().by_number(base_register);
        bool touches_pc = true; // Assume it does for now.

        switch ((current_insn & 0x0180) >> 7) {
        case 0x0: // RFEDB
          assert(false);
        case 0x1: // LDMIA/POP
          if (!(current_insn_2 & 0x8000)) {
            touches_pc = false;
          } else {
            uint8_t stack_values[36];
            t->read_bytes(base, stack_values);
            base--;
            base += __builtin_popcount(current_insn_2);
          }
          break;
        case 0x2: // LDMDB
          if (!(current_insn_2 & 0x8000)) {
            touches_pc = false;
          } else {
            // Decrement before, so do that now.
            base--;
          }
          break;
        case 0x3: // RFEIA
          assert(false);
        }

        if (touches_pc) {
          next_pc = t->read_mem(base);
        }
      } else if ((current_insn & 0xFFEF) == 0xEA4F && (current_insn_2 & 0xFFF0) == 0x0F00) {
        // MOV/MOVS PC
        assert(false);
      } else if ((current_insn & 0xFF70) == 0xF850 && (current_insn_2 & 0xF000) == 0xF000) {
        // LDR PC
        assert(false);
      } else if ((current_insn & 0xFFF0) == 0xE8D0) {
        if ((current_insn_2 & 0xFFE0) == 0xF000) {
          // TBB/TBH
          bool tbh = !!(current_insn_2 & 0x0010);
          uint8_t base_regno = current_insn & 0x000F;
          uint8_t index_regno = current_insn_2 & 0x000F;
          uint32_t index = t->regs().by_number(index_regno);
          uint16_t offset = 0;

          if (tbh) {
            remote_ptr<uint16_t> entry = t->regs().by_number(base_regno);
            if (base_regno == 15) {
              entry = t->regs().ip().to_data_ptr<uint16_t>() + 2;
            }
            entry += index;
            offset = t->read_mem(entry);
          } else {
            remote_ptr<uint8_t> entry = t->regs().by_number(base_regno);
            if (base_regno == 15) {
              entry = t->regs().ip().to_data_ptr<uint8_t>() + 4;
            }
            entry += index;
            offset = t->read_mem(entry);
          }

          LOG(debug) << "TB" << (tbh ? "H" : "B")
                     << " base_regno: " << HEX(base_regno)
                     << " index_regno: " << HEX(index_regno)
                     << " index value: " << index
                     << " offset: " << offset;

          next_pc = this_pc + 2 * (2 + offset);
        }
      }
    } else {
      // Normal Thumb instruction.
      LOG(debug) << "Normal thumb instruction " << HEX(current_insn);
      switch ((current_insn & 0xF000) >> 12) {
      case 0x0: // LSL/LSR
      case 0x1: // ASR/ADD/SUB
      case 0x2: // MOV/CMP
      case 0x3: // ADD/SUB
      case 0x5: // Load/store register
      case 0x6: // Load/store immediate
      case 0x7: // Load/store byte immediate
      case 0x8: // Load/store halfword immediate
      case 0x9: // Load/store stack
      case 0xA: // pc or sp relative add
      case 0xC: // Multiple load/store
        // In thumb mode none of these can modify the pc, because they can only
        // touch the first 8 registers.
        break;
      case 0x4: {
        if ((current_insn & 0x0F00) == 0x0700) {
          LOG(debug) << "bx/blx";
          // BX/BLX
          uint8_t regno = (current_insn & 0x0078) >> 3;
          assert(regno < 16);

          if (regno == 15) {
            // BX PC always switches to ARM mode.
            next_pc = this_pc + 3;
          } else {
            next_pc = t->regs().by_number(regno);
          }
        } else if ((current_insn & 0x0F87) == 0x0687) {
          // MOV pc, reg
          // Only ARM can use this to switch instruction sets.
          assert(false);
        }
        break;
      }
      case 0xB: {
        if ((current_insn & 0x0500) == 0x0100) {
          // CBZ/CBNZ
          LOG(debug) << "Handling CBZ/CNBZ";
          uint8_t offset = ((current_insn & 0x0200) >> 4) + ((current_insn & 0x00F8) >> 3);
          uint8_t regno = current_insn & 0x0007;

          LOG(debug) << "Calculated offset " << HEX(offset);

          bool branch_on_nonzero = !!(current_insn & 0x0800);
          if ((branch_on_nonzero && !!t->regs().by_number(regno)) ||
              (!branch_on_nonzero && !t->regs().by_number(regno))) {
            next_pc = this_pc + 2 * (offset + 2);
          }
        } else if ((current_insn & 0x0F00) == 0x0D00) {
          // POP {registers, pc}
          LOG(debug) << "Handling POP";
          uint32_t offset = __builtin_popcount(current_insn & 0x00FF);
          remote_ptr<uint32_t> sp = t->regs().by_number(/* SP # */ 13);
          next_pc = t->read_mem(sp + offset);
        }
        break;
      }
      case 0xD: { // Conditional branch
        uint8_t condition_block = (current_insn & 0x0F00) >> 8;
        LOG(debug) << "Handling conditional branch w/cond " << HEX(condition_block) << "\n          flags " << HEX(t->regs().flags());
        if (condition_block == 0xF) {
          // SWI.  We'll come back to the next instruction after the interrupt,
          // so next_pc is good enough for us.
        } else if (is_condition_true(condition_block, t->regs().flags())) {
          LOG(debug) << "Condition block evaluated as true";
          next_pc = this_pc + 2* (2 + sign_extended_offset(current_insn, 0, 7));
        }
        break;
      }
      case 0xE: // Unconditional branch
        LOG(debug) << "Handling unconditional branch";
        next_pc = this_pc + 2*(2 + sign_extended_offset(current_insn, 0, 10));
        LOG(debug) << "Calculated next_pc to be " << next_pc;
        break;
      case 0xF:
        // Anything with all four bits set is actually a thumb2 insn, which we
        // handled already.
        assert(false);
      default:
        assert(false);
      }
    }
  }

  LOG(debug) << "Calculated next execution point at " << next_pc << ", breaking";

  // next_pc now tells us where to set our breakpoint.
  t->vm()->add_breakpoint(next_pc, TRAP_STEPI_INTERNAL_EMULATION);

  if (how == RESUME_SINGLESTEP)
    return RESUME_SYSCALL;
  else
    return RESUME_SYSEMU;
}

} // namespace rr
