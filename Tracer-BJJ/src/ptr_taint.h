#ifndef _TRACER_BJJ_PTR_TAINT_H_
#define _TRACER_BJJ_PTR_TAINT_H_

#include "common.h"
#include "rtag_helper.h"
#include "tagmap_helper.h"

void PIN_FAST_ANALYSIS_CALL hdlr_m2r_xfer_deref_before(THREADID tid, ADDRINT src, uint32_t src_base);
void PIN_FAST_ANALYSIS_CALL hdlr_m2r_xfer_deref_after(THREADID tid, ADDRINT src, uint32_t src_base);
void PIN_FAST_ANALYSIS_CALL hdlr_r2m_xfer_deref_before(THREADID tid, ADDRINT dst, uint32_t dst_base);

#endif  // _TRACER_BJJ_PTR_TAINT_H_