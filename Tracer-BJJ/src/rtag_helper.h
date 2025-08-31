#ifndef _SYMTABLEDETECTOR_SRC_RTAG_HELPER_H_
#define _SYMTABLEDETECTOR_SRC_RTAG_HELPER_H_

#include "pin.H"
#include "ins_helper.h"
#include <stdio.h>
#include <iostream>

extern thread_ctx_t *threads_ctx;

// REG general_regs[] = { REG_RDI, REG_EDI, REG_DI, REG_DIL, REG_RSI, REG_ESI, REG_SI, REG_SIL, REG_RBP, REG_EBP, REG_BP, REG_BPL, REG_RSP, REG_ESP, REG_SP, REG_SPL, REG_RAX, REG_EAX, REG_AX, REG_AH, REG_AL, REG_RBX, REG_EBX, REG_BX, REG_BH, REG_BL, REG_RCX, REG_ECX, REG_CX, REG_CH, REG_CL, REG_RDX, REG_EDX, REG_DX, REG_DH, REG_DL, REG_R8, REG_R8D, REG_R8W, REG_R8B, REG_R9, REG_R9D, REG_R9W, REG_R9B, REG_R10, REG_R10D, REG_R10W, REG_R10B, REG_R11, REG_R11D, REG_R11W, REG_R11B, REG_R12, REG_R12D, REG_R12W, REG_R12B, REG_R13, REG_R13D, REG_R13W, REG_R13B, REG_R14, REG_R14D, REG_R14W, REG_R14B, REG_R15, REG_R15D, REG_R15W, REG_R15B };
static const REG gr64[] = { REG_RDI, REG_RSI, REG_RBP, REG_RSP, REG_RAX, REG_RBX, REG_RCX, REG_RDX, REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15 };

inline void _print_rtag_gr64(std::ostream *out, THREADID tid, REG reg, std::string header) {
  tag_t tag;

  for (size_t pos = 0; pos < 8; pos++) {
    tag = RTAG[REG_INDX(reg)][pos];
    if (tag)
      *out << header << "tid: " << tid << " , RTAG[" << REG_StringShort(reg) << "][" << std::dec << 8 * pos << "-" << 8 * (pos + 1) - 1 << "]: " << tag_sprint(tag) << std::endl;
  }
}

inline void print_rtag_gr64(std::ostream *out, THREADID tid, REG reg) {
  _print_rtag_gr64(out, tid, reg, "");
}

inline void print_rtag_gr64(std::ostream *out, THREADID tid, REG reg, std::string header) {
  _print_rtag_gr64(out, tid, reg, header);
}

inline void _rtag_explore(std::ostream *out, THREADID tid) {
  *out << "[explore] Dumping all tags in the general purpose registers" << std::endl;

  for (size_t reg_idx = 0; reg_idx < sizeof(gr64)/sizeof(gr64[0]); reg_idx++) {
    print_rtag_gr64(out, tid, gr64[reg_idx], "[explore]:");
  }
}

inline void rtag_explore(THREADID tid) {
    _rtag_explore(&std::cout, tid);
}

inline void rtag_explore(std::ostream *out, THREADID tid) {
    _rtag_explore(out, tid);
}

#endif  // _SYMTABLEDETECTOR_SRC_RTAG_HELPER_H_