#ifndef _EXTRACTOR_BJJ_OUTPUT_H_
#define _EXTRACTOR_BJJ_OUTPUT_H_

#include "common.h"
#include "config.h"
#include "extract.h"
#include "payload.h"
#include <fstream>

using std::ofstream;


VOID save_payload_to_json(const Payload payload, const string& file_name);
VOID save_payload_to_header(const Payload payload, const string& file_name);

#endif  // _EXTRACTOR_BJJ_OUTPUT_H_