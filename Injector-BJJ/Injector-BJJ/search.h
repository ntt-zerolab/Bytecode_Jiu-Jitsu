#ifndef _INJECTOR_SEARCH_H_
#define _INJECTOR_SEARCH_H_

#include <nlohmann/json.hpp>
#include "memory.h"
#include "payload.h"
#include <deque>
#include <regex>
#include <utility>
#include <iomanip>
#include <iostream>
#include <Windows.h>

using json = nlohmann::json;

const uint8_t kSearchTextTypeChar = 0;
const uint8_t kSearchTextTypeWchar = 1;


typedef struct _Search {
    uint8_t type;
    union {
        char* pattern_mbs;
        wchar_t* pattern_wcs;
    };
    off_t value_object_offset;
} Search;

void deserialize_search(std::string search_json_string, Search& search);
char* generate_search_pattern(wchar_t* search_string);
char* generate_search_pattern(int64_t search_value);
std::pair<ULONGLONG, SIZE_T> search_characteristic_string(BYTE* buf, SIZE_T buf_len, Search search);
void log_search_result(BYTE *content, LPVOID content_base_addr, ULONGLONG match_offset, SIZE_T match_len);
LPVOID find_management_structure(std::list<BinaryContent> contents, LPVOID value_addr, ptrdiff_t value_offset, ptrdiff_t struct_offset);
LPVOID backtrack(std::list<BinaryContent> contents, LPVOID found_addr, std::deque<ptrdiff_t> member_offsets);

#endif // _INJECTOR_SEARCH_H_