#include "ptr_taint.h"


void PIN_FAST_ANALYSIS_CALL hdlr_m2r_xfer_deref_before(THREADID tid,
                                                       ADDRINT src,
                                                       uint32_t src_base) {
  tag_t src_tag, dst_tag;
  tag_t deref_ptr_tag, deref_dst_tag;

  deref_ptr_tag = tag_alloc<tag_t>(10000);
  deref_dst_tag = tag_alloc<tag_t>(20000);

  for (size_t i = 0; i < 8; i++) {
    src_tag = RTAG[src_base][i];
    RTAG[src_base][i] = tag_combine(src_tag, deref_ptr_tag);
    dst_tag = MTAG(src + i);
    tagmap_setb(src + i, tag_combine(dst_tag, deref_dst_tag));
  }
}

void PIN_FAST_ANALYSIS_CALL hdlr_m2r_xfer_deref_after(THREADID tid,
                                                      ADDRINT src,
                                                      uint32_t src_base) {
  tag_t src_tag, dst_tag;
  tag_t deref_ptr_tag, deref_dst_tag;

  deref_ptr_tag = tag_alloc<tag_t>(10000);
  deref_dst_tag = tag_alloc<tag_t>(20000);

  for (size_t i = 0; i < 8; i++) {
    src_tag = RTAG[src_base][i];
    RTAG[src_base][i] = tag_combine(src_tag, deref_ptr_tag);
    dst_tag = MTAG(src + i);
    tagmap_setb(src + i, tag_combine(dst_tag, deref_dst_tag));
  }
}


void PIN_FAST_ANALYSIS_CALL hdlr_r2m_xfer_deref_before(THREADID tid,
                                                       ADDRINT dst,
                                                       uint32_t dst_base) {
  tag_t src_tag, dst_tag;
  tag_t deref_ptr_tag, deref_dst_tag;

  deref_ptr_tag = tag_alloc<tag_t>(10000);
  deref_dst_tag = tag_alloc<tag_t>(20000);

  for (size_t i = 0; i < 8; i++) {
    src_tag = RTAG[dst_base][i];
    RTAG[dst_base][i] = tag_combine(src_tag, deref_ptr_tag);
    dst_tag = MTAG(dst + i);
    tagmap_setb(dst + i, tag_combine(dst_tag, deref_dst_tag));
  }
}