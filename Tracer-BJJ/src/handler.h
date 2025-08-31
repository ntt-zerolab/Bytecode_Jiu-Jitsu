#ifndef _TRACER_BJJ_HANDLER_H_
#define _TRACER_BJJ_HANDLER_H_

#include "common.h"
#include "config.h"
#include "defs.h"
#include "log.h"
#include "rtag_helper.h"
#include "tagmap_helper.h"

VOID hdlr_stack_ptr_write_before(ADDRINT insn_ptr, ADDRINT stack_ptr);
VOID hdlr_stack_ptr_write_after(ADDRINT insn_ptr, ADDRINT stack_ptr);
VOID hdlr_memread(uint32_t memaccess_type, ADDRINT insn_ptr, ADDRINT target_addr, ADDRINT base_addr, ADDRINT index, ADDRINT disp, ADDRINT size);
VOID hdlr_memwrite_before(ADDRINT target_addr);
VOID hdlr_memwrite_after(uint32_t memaccess_type, ADDRINT insn_ptr, ADDRINT target_addr, ADDRINT base_addr, ADDRINT index, ADDRINT disp, ADDRINT size);
VOID hdlr_interp_func_before(THREADID tid, REG rdi, REG rsi, ADDRINT arg1, ADDRINT arg2);
VOID hdlr_interp_func_after(THREADID tid);
VOID hdlr_mov_stack_read_before(ADDRINT ip, ADDRINT target_addr, Config *config);
VOID hdlr_mov_stack_read_after(ADDRINT ip, UINT32 vmop, Config *config);

#endif  // _TRACER_BJJ_HANDLER_H_