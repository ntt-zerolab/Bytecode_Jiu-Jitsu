#ifndef _TRACER_BJJ_LOG_H_
#define _TRACER_BJJ_LOG_H_

#include "common.h"
#include "defs.h"

VOID log_stack(ADDRINT insn_ptr, ADDRINT stack_ptr);
VOID log_memaccess(ADDRINT rw_type, uint32_t memaccess_type, ADDRINT insn_ptr, ADDRINT target_addr, ADDRINT base_addr, ADDRINT index, ADDRINT disp, ADDRINT size);

#endif  // _TRACER_BJJ_LOG_H_