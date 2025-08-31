#include "search.h"

extern std::ostream *out;


void deserialize_search(std::string search_json_string, Search& search) {
    auto search_json = json::parse(search_json_string);

    try {
        search.type = search_json.at("type").get<uint8_t>();

        if (search.type == kSearchTextTypeChar) {
            std::string search_pattern = search_json.at("pattern").get<std::string>();
            search.pattern_mbs = new char[search_pattern.size() + 1];
            strncpy_s(search.pattern_mbs, search_pattern.size() + 1, search_pattern.c_str(), search_pattern.size() + 1);
        }
        else if (search.type == kSearchTextTypeWchar) {
            std::wstring search_pattern = search_json.at("pattern").get<std::wstring>();
            search.pattern_wcs = new wchar_t[search_pattern.size() + 1];
            wcsncpy_s(search.pattern_wcs, search_pattern.size() + 1, search_pattern.c_str(), search_pattern.size() + 1);
        }
        else {
            std::exit(1);
        }

        search.value_object_offset = search_json.at("value_object_offset").get<off_t>();
    }
    catch (const std::exception& err) {
        std::exit(1);
    }
}

char convert_order_to_char_upper(int order) {
    int val = order / 16;
    if (val < 10)
        val += '0';
    else
        val += 'a' - 10;

    return val;
}

char convert_order_to_char_lower(int order) {
    int val = order % 16;
    if (val < 10)
        val += '0';
    else
        val += 'a' - 10;

    return val;
}

char* generate_search_pattern(wchar_t* search_string) {
    char* search_pattern;
    std::string search_pattern_str;
    SIZE_T len = wcslen(search_string);

    for (auto i = 0; i < len * 2; i++) {
        search_pattern_str += "\\x";
        int order = (int)((char*)search_string)[i];
        search_pattern_str += convert_order_to_char_upper(order);
        search_pattern_str += convert_order_to_char_lower(order);
    }

    search_pattern = new char[search_pattern_str.size() + 1];
    memcpy(search_pattern, search_pattern_str.data(), search_pattern_str.size());
    search_pattern[search_pattern_str.size()] = '\0';

    return search_pattern;
}

char *generate_search_pattern(int64_t search_value) {
    char *pattern;
    int pattern_len;
    uint8_t search_value_bytes[sizeof(LPVOID)];

    pattern_len = sizeof(LPVOID) * 8;
    pattern = new char[pattern_len];
    memset(pattern, 0x0, pattern_len);

    for (auto i = 0; i < sizeof(LPVOID); i++) {
        search_value_bytes[i] = (uint8_t)(search_value % 0x100);
        search_value /= 0x100;
    }

    *out << "Target value (hex): 0x";
    for (auto i = 0; i < sizeof(LPVOID); i++) {
        *out << std::hex << std::setfill('0') << std::setw(2)
             << (int)search_value_bytes[i];
    }
    *out << std::endl;

#ifdef _WIN64
    snprintf(pattern, pattern_len, "\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x",
            search_value_bytes[0],
            search_value_bytes[1],
            search_value_bytes[2],
            search_value_bytes[3],
            search_value_bytes[4],
            search_value_bytes[5],
            search_value_bytes[6],
            search_value_bytes[7]);
#elif _WIN32
    snprintf(pattern, pattern_len, "\\x%02x\\x%02x\\x%02x\\x%02x",
            search_value_bytes[0],
            search_value_bytes[1],
            search_value_bytes[2],
            search_value_bytes[3]);
#endif

    *out << "Search pattern: "
         << pattern
         << std::endl;

    return pattern;
}

std::pair<ULONGLONG, SIZE_T> search_characteristic_string(BYTE *buf, SIZE_T buf_len, Search search) {
    auto m = std::cmatch {};

    std::regex p;
    if (search.type == kSearchTextTypeChar) {
        p = std::regex(search.pattern_mbs);
    }
    else if (search.type == kSearchTextTypeWchar) {
        char* c = (char*)search.pattern_wcs;
        char* search_pattern = generate_search_pattern(search.pattern_wcs);
        p = std::regex(search_pattern);
    }

    if (std::regex_search((const char*)buf, (const char*)buf + buf_len, m, p))
        return std::make_pair(m.position(), m.length());
    else
        return std::make_pair(0, 0);
}

std::pair<ULONGLONG, SIZE_T> search_ptr(BYTE *buf, SIZE_T buf_len, char *pattern) {
    auto m = std::cmatch{};

    auto p = std::regex(pattern);
    if (std::regex_search((const char*)buf, (const char*)buf + buf_len, m, p))
        return std::make_pair(m.position(), m.length());
    else
        return std::make_pair(0, 0);
}

void log_search_result(BYTE *content, LPVOID content_base_addr, ULONGLONG match_offset, SIZE_T match_len) {
    *out << "trace: search, base addr: 0x"
         << content_base_addr
         << ", offset: 0x"
         << std::hex << std::setfill('0') << std::setw(4)
         << match_offset
         << ", len: "
         << match_len
         << ", hex: 0x";

    for (auto i = match_offset; i < match_offset + match_len; i++)
        *out << std::hex << std::setfill('0') << std::setw(2)
             << (int)content[i];

    *out << ", bytes: ";
    for (auto i = match_offset; i < match_offset + match_len; i++)
        *out << content[i];

    *out << std::endl;
}

LPVOID find_management_structure(std::list<BinaryContent> contents, LPVOID value_addr, ptrdiff_t value_offset, ptrdiff_t struct_offset) {
    LPVOID management_structure_addr;
    LPVOID value_object_addr = (LPVOID)((int64_t)value_addr - value_offset);

    char *pattern = generate_search_pattern((int64_t)value_object_addr);
    auto m = std::cmatch {};
    auto p = std::regex(pattern);

    off_t block_offset;
    bool found;
    management_structure_addr = NULL;
    for (auto iter = contents.begin(); iter != contents.end(); iter++) {
        auto [match_offset, match_len] = search_ptr(iter->bytes, iter->len, pattern);
        if (match_len != 0) {
            log_search_result(iter->bytes, iter->addr, match_offset, match_len);
            std::deque<ptrdiff_t> member_offsets;
            member_offsets.push_back(0x1f0);
            management_structure_addr = backtrack(contents, (LPVOID)((int64_t)iter->addr + match_offset), member_offsets);
        }
    }

    return management_structure_addr;
}

LPVOID backtrack(std::list<BinaryContent> contents, LPVOID found_addr, std::deque<ptrdiff_t> member_offsets) {
    LPVOID backtracked_addr;
    ptrdiff_t member_offset;

    if (member_offsets.empty()) return found_addr;

    member_offset = member_offsets.front();
    member_offsets.pop_front();
    *out << "Member offset: 0x"
         << std::hex << std::setfill('0') << std::setw(2)
         << member_offset
         << ", Deque size: "
         << std::dec
         << member_offsets.size()
         << std::endl;
    LPVOID struct_base_addr = (LPVOID)((int64_t)found_addr - member_offset);

    char *pattern = generate_search_pattern((int64_t)struct_base_addr);
    auto m = std::cmatch {};
    auto p = std::regex(pattern);

    for (auto iter = contents.begin(); iter != contents.end(); iter++) {
        auto [match_offset, match_len] = search_ptr(iter->bytes, iter->len, pattern);
        if (match_len != 0) {
            log_search_result(iter->bytes, iter->addr, match_offset, match_len);
            backtracked_addr = backtrack(contents, (LPVOID)((int64_t)iter->addr + match_offset), member_offsets);
            member_offsets.push_front(member_offset);

            return backtracked_addr;
        }
    }

    return NULL;
}