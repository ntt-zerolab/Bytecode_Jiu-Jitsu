#include "Extractor-BJJ.h"


std::string output_payload_file_name;
UINT8 output_payload_file_type;

// Map to store allocated heap memory and their sizes
unordered_map<ADDRINT, UINT32> heap_allocations;

// Mutex to protect heap_allocations
PIN_MUTEX heap_mutex;


KNOB<std::string> KnobConfigFile(KNOB_MODE_WRITEONCE, "pintool", "c", "", "specify file name for the input config");
KNOB<std::string> KnobPayloadFileType(KNOB_MODE_WRITEONCE, "pintool", "p", "", "specify file type of the output payload [JSON/C_HEADER]");
KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "", "specify file name for the output payload");


INT32 Usage() {
    std::cerr << "This tool extracts bytecode and symbol tables for Bytecode Jiu-Jitsu." << endl;
    std::cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

// Instrumentation for target functions
VOID hook_interp_func(IMG img, const Config &config) {
  string image_name = IMG_Name(img);
  ADDRINT image_base = IMG_LowAddress(img);

  if (image_name == config.interp_module_name) {
    RTN rtn = RTN_CreateAt(image_base + config.interp_func_offset, "interp_func");

    if (RTN_Valid(rtn)) {
      RTN_Open(rtn);

      RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)hdlr_interp_func_before,
          IARG_CONST_CONTEXT,
          IARG_REG_VALUE, REG_STACK_PTR,
          IARG_PTR, &config,
          IARG_END);

      RTN_Close(rtn);
    } else {
      cout << "Invalid RTN" << endl;
    }
  }
}

VOID hook_heap_allocation(IMG img) {
  RTN rtn;

  for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym)) {
      string undFuncName = PIN_UndecorateSymbolName(SYM_Name(sym), UNDECORATION_NAME_ONLY);

    if (undFuncName == "CoTaskMemAlloc") {
      rtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));
      if (RTN_Valid(rtn)) {
        RTN_Open(rtn);

        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)hdlr_CoTaskMemAlloc_before,
            IARG_ADDRINT, "CoTaskMemAlloc",
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)hdlr_CoTaskMemAlloc_after,
            IARG_ADDRINT, "CoTaskMemAlloc",
            IARG_FUNCRET_EXITPOINT_VALUE,
            IARG_END);

        RTN_Close(rtn);
      } else {
        cout << "Invalid RTN" << endl;
      }
    }

    if (undFuncName == "GlobalAlloc") {
      rtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));
      if (RTN_Valid(rtn)) {
        RTN_Open(rtn);

        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)hdlr_GlobalAlloc_before,
            IARG_ADDRINT, "GlobalAlloc",
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)hdlr_GlobalAlloc_after,
            IARG_ADDRINT, "GlobalAlloc",
            IARG_FUNCRET_EXITPOINT_VALUE,
            IARG_END);

        RTN_Close(rtn);
      } else {
        cout << "Invalid RTN" << endl;
      }
    }

    if (undFuncName == "LocalAlloc") {
      rtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));
      if (RTN_Valid(rtn)) {
        RTN_Open(rtn);

        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)hdlr_LocalAlloc_before,
            IARG_ADDRINT, "LocalAlloc",
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)hdlr_LocalAlloc_after,
            IARG_ADDRINT, "LocalAlloc",
            IARG_FUNCRET_EXITPOINT_VALUE,
            IARG_END);

        RTN_Close(rtn);
      } else {
        cout << "Invalid RTN" << endl;
      }
    }

    if (undFuncName == "HeapAlloc") {
      rtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));
      if (RTN_Valid(rtn)) {
        RTN_Open(rtn);

        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)hdlr_HeapAlloc_before,
            IARG_ADDRINT, "HeapAlloc",
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)hdlr_HeapAlloc_after,
            IARG_ADDRINT, "HeapAlloc",
            IARG_FUNCRET_EXITPOINT_VALUE,
            IARG_END);

        RTN_Close(rtn);
      } else {
        cout << "Invalid RTN" << endl;
      }
    }

    if (undFuncName == "malloc") {
        rtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));
        if (RTN_Valid(rtn)) {
            RTN_Open(rtn);

            RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)hdlr_malloc_before,
                IARG_ADDRINT, "malloc",
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_END);

            RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)hdlr_malloc_after,
                IARG_ADDRINT, "malloc",
                IARG_FUNCRET_EXITPOINT_VALUE,
                IARG_END);

            RTN_Close(rtn);
        }
        else {
            cout << "Invalid RTN" << endl;
        }
    }

    if (undFuncName == "operator new") {
      rtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));
      if (RTN_Valid(rtn)) {
        RTN_Open(rtn);

        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)hdlr_operator_new_before,
            IARG_ADDRINT, "operator new",
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)hdlr_operator_new_after,
            IARG_ADDRINT, "operator new",
            IARG_FUNCRET_EXITPOINT_VALUE,
            IARG_END);

        RTN_Close(rtn);
      }
      else {
        cout << "Invalid RTN" << endl;
      }
    }

    if (undFuncName == "operator new[]") {
      rtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));
      if (RTN_Valid(rtn)) {
        RTN_Open(rtn);

        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)hdlr_operator_new_before,
            IARG_ADDRINT, "operator new[]",
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)hdlr_operator_new_after,
            IARG_ADDRINT, "operator new[]",
            IARG_FUNCRET_EXITPOINT_VALUE,
            IARG_END);

        RTN_Close(rtn);
      }
      else {
        cout << "Invalid RTN" << endl;
      }
    }

    if (undFuncName == "VirtualAlloc") {
      rtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));
      if (RTN_Valid(rtn)) {
        RTN_Open(rtn);

        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)hdlr_VirtualAlloc_before,
            IARG_ADDRINT, "VirtualAlloc",
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
            IARG_END);

        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)hdlr_VirtualAlloc_after,
            IARG_ADDRINT, "VirtualAlloc",
            IARG_FUNCRET_EXITPOINT_VALUE,
            IARG_END);

        RTN_Close(rtn);
      } else {
        cout << "Invalid RTN" << endl;
      }
    }
  }
}

// Image load callback
VOID ImageLoad(IMG img, VOID *v) {
  Config *config;
  ADDRINT image_base;
  string image_name;

  image_name = IMG_Name(img);
  image_base = IMG_LowAddress(img);

  cout << "[+] Loading image name: " << image_name << endl;
  cout << "[+] Image base: "
       << (void *)image_base
       << endl;

  config = reinterpret_cast<Config *>(v);
  hook_interp_func(img, *config);
  hook_heap_allocation(img);
}


int main(int argc, char **argv) {
  PIN_InitSymbols();
  // Initialize Pin
  if (PIN_Init(argc, argv)) {
    return Usage();
  }

  // Initialize mutex
  PIN_MutexInit(&heap_mutex);

  // Load ConfigIn
  Config* config = new Config;
  config->interp_module_name = "C:\\Windows\\System32\\vbscript.dll";
  config->interp_func_offset = 0x84b0;
  config->management_structure_index = 1;
  output_payload_file_name = "test_payload.json";
  output_payload_file_type = kPayloadFileTypeJson;
  config->bytecode = { { 0x1e0 } };
  config->symbol_tables = { { 2, 0, { 0x1f0 }, 0 } };

  string config_file = KnobConfigFile.Value();
  if (!config_file.empty()) {
      std::string config_string;
      cout << "[+] Config file: " << config_file << endl;

      std::ifstream config_f(config_file);
      if (!config_f) {
          std::exit(1);
      }
      auto ss = std::ostringstream{};
      ss << config_f.rdbuf();
      config_string = ss.str();

      if (!config_string.empty()) {
          // To be fixed: JSON deserialization with nlohmann/json does not work properly.
          // deserialize_config(config_string, *config);
      }
  }

  string payload_file_type = KnobPayloadFileType.Value();
  if (payload_file_type == "JSON") {
      cout << "[+] Output payload file type: JSON" << endl;
      output_payload_file_type = kPayloadFileTypeJson;
  }
  else if (payload_file_type == "C_HEADER") {
      cout << "[+] Output payload file type: C header" << endl;
      output_payload_file_type = kPayloadFileTypeCHeader;
  }
  else {
      cout << "[+] No valid payload file type was specified. The default value of JSON has been selected." << endl;
      output_payload_file_type = kPayloadFileTypeJson;
  }

  string payload_file_name = KnobOutputFile.Value();
  if (!payload_file_name.empty()) {
      cout << "[+] Output file: " << payload_file_name << endl;
      output_payload_file_name = payload_file_name;
  }

  // Register image load callback
  IMG_AddInstrumentFunction(ImageLoad, config);

  // Start the program
  PIN_StartProgram();

  return 0;
}
