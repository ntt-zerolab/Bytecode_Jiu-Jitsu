#ifndef _EXTRACTOR_BJJ_HANDLER_H_
#define _EXTRACTOR_BJJ_HANDLER_H_

#include "config.h"
#include "common.h"
#include "debug.h"
#include "extract.h"
#include "output.h"
#include "payload.h"

VOID hdlr_interp_func_before(CONTEXT *ctxt, ADDRINT *stack_ptr, Config *config_in);
VOID hdlr_CoTaskMemAlloc_before(CHAR* name, size_t bytes);
VOID hdlr_CoTaskMemAlloc_after(CHAR* name, ADDRINT allocated_addr);
VOID hdlr_GlobalAlloc_before(CHAR* name, size_t bytes);
VOID hdlr_GlobalAlloc_after(CHAR* name, ADDRINT allocated_addr);
VOID hdlr_LocalAlloc_before(CHAR* name, size_t bytes);
VOID hdlr_LocalAlloc_after(CHAR* name, ADDRINT allocated_addr);
VOID hdlr_HeapAlloc_before(CHAR *name, size_t bytes);
VOID hdlr_HeapAlloc_after(CHAR *name, ADDRINT allocated_addr);
VOID hdlr_malloc_before(CHAR *name, size_t bytes);
VOID hdlr_malloc_after(CHAR *name, ADDRINT allocated_addr);
VOID hdlr_operator_new_before(CHAR* name, size_t bytes);
VOID hdlr_operator_new_after(CHAR* name, ADDRINT allocated_addr);
VOID hdlr_VirtualAlloc_before(CHAR* name, size_t bytes);
VOID hdlr_VirtualAlloc_after(CHAR* name, ADDRINT allocated_addr);

#endif  // _EXTRACTOR_BJJ_HANDLER_H_