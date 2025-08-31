#ifndef _TC_TAGMAP_H_
#define _TC_TAGMAP_H_

#include "debug.h"
#include "libdft_api.h"
#include "pin.H"
#include "tagmap.h"
#include <stdio.h>
#include <iostream>

#define DEBUG_INFO 1
#define EXCLUDE_KERNEL 1
#define KERNEL_BASE 0xffffffff00000000

#define FORMAT_QUERY_CHECKTAINT "[%[a-zA-Z0-9_]][query][check taint] addr: 0x%llx, size: %llu"
#define FORMAT_QUERY_SETTAINT "[%[a-zA-Z0-9_]][query][set taint] addr: 0x%llx, size: %llu, lb: %d"
#define FORMAT_QUERY_FORCETAINT "[%[a-zA-Z0-9_]][query][force taint] src addr: 0x%llx, dst addr: 0x%llx, src size: %llu, dst size: %llu\n"

extern tag_dir_t tag_dir;

inline void _print_mtag(std::ostream *out, tag_t tag, ADDRINT addr, std::string header) {
  uint8_t val;
  size_t nbytes;

  if (EXCLUDE_KERNEL && addr >= KERNEL_BASE) return;

  nbytes = PIN_SafeCopy(&val, (void *)addr, 1);

  *out << "trace: memtaint, addr: " 
       << (void *)addr
       << ", tag: "
       << tag_sprint(tag);

  if (nbytes != 0)
    *out << ", byte: 0x"
         << std::hex << std::setfill('0') << std::setw(2)
         << (uint32_t)val
         << ", char: "
         << std::dec
         << val
         << std::endl;
  else
    *out << ", not mapped" << std::endl;
}

inline void print_mtag(std::ostream *out, tag_t tag, ADDRINT addr) {
  _print_mtag(out, tag, addr, "");
}

inline void print_mtag(std::ostream *out, tag_t tag, ADDRINT addr, std::string header) {
  _print_mtag(out, tag, addr, header);
}

inline void _tagmap_explore(std::ostream *out) {
  tag_table_t *table;
  tag_page_t *page;
  tag_t tag;
  ADDRINT addr;

  if (EXCLUDE_KERNEL)
    *out << "[explore] Dumping all tags in the tagmap except kernel memory regions" << std::endl;
  else
    *out << "[explore] Dumping all tags in the tagmap" << std::endl;

  for (uint64_t i = 0; i < TOP_DIR_SZ; i++) {
    if (tag_dir.table[i]) {
      table = tag_dir.table[i];
      for (uint64_t j = 0; j < PAGETABLE_SZ; j++) {
        if ((*table).page[j]) {
          page = (*table).page[j];
          if (page != NULL) {
            for (uint64_t k = 0; k < PAGE_SIZE; k++) {
              tag = (*page).tag[k];
              if (tag) {
                addr = (i << PAGETABLE_BITS) + (j << PAGE_BITS) + k;
                print_mtag(out, tag, addr, "[explore]:");
              }
            }
          }
        }
      }
    }
  }
}

inline void tagmap_explore() {
  _tagmap_explore(&std::cout);
}

inline void tagmap_explore(std::ostream *out) {
  _tagmap_explore(out);
}

inline void tagmap_force_propagation(const char *fname, ADDRINT src, ADDRINT dst, size_t src_size, size_t dst_size) {
  if (src_size == dst_size) {
    // simply propagate tags byte-by-byte
    for (uint64_t i = 0; i < src_size; i++) {
      tag_t t = tagmap_getb(src + i);
      tagmap_setb(dst + i, t);
      LOGD( "[%s][force propagation]:tags[%p]: %s, dst: %p\n", fname, (void *)(src + i), tag_sprint(tagmap_getb(src+i)).c_str(), (void *)(dst + i));
    }
  } else {
    // combine all the tags of src 
    tag_t t = tagmap_getn(src, src_size);
    // add the marged tags to dst
    for (uint64_t i = 0; i < dst_size; i++) {
      tagmap_setb(dst + i, t);
      LOGD( "[%s][force propagation]:tags[%p-%p]: %s, dst: %p\n", fname, (void *)(src), (void *)(src + src_size), tag_sprint(t).c_str(), (void *)(dst + i));
    }
  }
}

inline void tagmap_set_taint(const char *fname, ADDRINT addr, size_t size, int color) {
  LOGD( "[%s][debug] val: %d\n", fname, *(int32_t *)addr);
  LOGD( "[%s][debug] size: %ld\n", fname, size);
  for (uint64_t i = 0; i < size; i++) {
    tag_t t = tag_alloc<tag_t>(color + (int)i);
    tagmap_setb(addr + i, t);
    LOGD( "[%s][set taint]:tags[%p]: %s\n", fname, (void *)(addr + i),
	tag_sprint(tagmap_getb(addr + i)).c_str());
  }
}

inline void tagmap_check_taint(const char *fname, ADDRINT addr, size_t size) {
  LOGD( "[%s][debug] addr: %p\n", fname, (char *)addr);
  LOGD( "[%s][debug] val: %s\n", fname, (char *)addr);
  LOGD( "[%s][debug] size: %ld\n", fname, size);
  for (uint64_t i = 0; i < size; i++) {
    LOGD( "[%s][check taint]:tags[%p]: %s\n", fname, (void *)(addr + i),
	tag_sprint(tagmap_getb(addr + i)).c_str());
  }
}

inline bool tagmap_detect_undertaint(const char *fname, ADDRINT addr, size_t size, double threshold) {
  tagmap_check_taint(fname, addr, size);

  uint64_t taint_count = 0;
  for (uint64_t i = 0; i < size; i++)
    if (tagmap_getb(addr + i) > 0) taint_count++;

  LOGD( "[%s][debug] size: %ld\n", fname, size);
  LOGD( "[%s][debug] taint_count: %ld\n", fname, taint_count);
  return ((double)taint_count / (double)size) < threshold;
}

inline void tagmap_process_query(char *buf) {
  char fname[128];
  ADDRINT addr;
  ADDRINT src;
  ADDRINT dst;
  size_t size;
  size_t src_size;
  size_t dst_size;
  int color;

  if (sscanf((const char *)buf, FORMAT_QUERY_SETTAINT, fname, &addr, &size, &color) == 4) {
    tagmap_set_taint(fname, addr, size, color);
  } else if (sscanf((const char *)buf, FORMAT_QUERY_CHECKTAINT, fname, &addr, &size) == 3) {
    tagmap_check_taint(fname, addr, size);
  } else if (sscanf((const char *)buf, FORMAT_QUERY_FORCETAINT, fname, &src, &dst, &src_size, &dst_size) == 5) {
    tagmap_force_propagation(fname, src, dst, src_size, dst_size);
  } else {
    LOGD( "%s\n", buf);
  }
}

#endif // _TC_TAGMAP_H_