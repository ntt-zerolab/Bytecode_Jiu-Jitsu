#ifndef _EXTRACTOR_BJJ_EXTRACTOR_BJJ_H_
#define _EXTRACTOR_BJJ_EXTRACTOR_BJJ_H_

#include "pin.H"
#include "config.h"
#include "common.h"
#include "handler.h"
#include <fstream>
#include <unordered_map>

using std::unordered_map;

VOID hook_interp_func(IMG img, const Config &config);
VOID hook_heap_allocation(IMG img);
VOID ImageLoad(IMG img, VOID *v);

#endif  // _EXTRACTOR_BJJ_EXTRACTOR_BJJ_H_