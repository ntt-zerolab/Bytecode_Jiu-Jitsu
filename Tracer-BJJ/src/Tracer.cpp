#include "Tracer-BJJ.h"

#define DEBUG_INFO 1

std::ostream *out = &cout;

PIN_LOCK lock;
ADDRINT target_image_base = 0x0;
ADDRINT target_image_end = 0x0;
ADDRINT memwrite_addr = 0x0;

KNOB<std::string> KnobConfigFile(KNOB_MODE_WRITEONCE, "pintool", "c", "", "specify a config file name.");
KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "", "specify file name for the trace output.");


INT32 Usage() {
    std::cerr << "This tool traces memory accesses and taint propagation for Bytecode Jiu-Jitsu." << endl;
    std::cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

VOID Image(IMG img, VOID *v) {
    Config *config = (Config *)v;

    string image_name = IMG_Name(img);
    ADDRINT image_base = IMG_LowAddress(img);
    int image_id = IMG_Id(img);
    size_t image_size = IMG_HighAddress(img) - image_base;

    *out << "trace: load, image name: "
         << image_name
         << ", ID: "
         << std::dec
         << image_id
         << ", image base: "
         << (void *)image_base
         << ", image size: 0x"
         << std::hex << std::setfill('0') << std::setw(8)
         << image_size
         << endl;

    if (image_name == config->target_module_name) {
        target_image_base = image_base;
        target_image_end = image_base + image_size;

        RTN rtn_interp_func = RTN_CreateAt(image_base + config->interp_func_offset, "interp_func");
        if (RTN_Valid(rtn_interp_func)) {
            RTN_Open(rtn_interp_func);
            RTN_InsertCall(rtn_interp_func, IPOINT_BEFORE, (AFUNPTR)hdlr_interp_func_before,
                    IARG_THREAD_ID,
                    IARG_UINT32, REG_RDI,
                    IARG_UINT32, REG_RSI,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_END);
            RTN_InsertCall(rtn_interp_func, IPOINT_AFTER, (AFUNPTR)hdlr_interp_func_after,
                    IARG_THREAD_ID,
                    IARG_END);
            RTN_Close(rtn_interp_func);
        }

    }
}

VOID Ins(INS ins, void * v) {
    Config *config = (Config *)v;
    uint32_t memaccess_type;
    
    if (INS_IsValidForIpointAfter(ins) && INS_IsMemoryRead(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)hdlr_mov_stack_read_before,
                IARG_INST_PTR,
                IARG_MEMORYREAD_EA,
                IARG_ADDRINT, (ADDRINT)config,
                IARG_END);
        INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)hdlr_mov_stack_read_after,
                IARG_INST_PTR,
                IARG_REG_VALUE, REG_EAX,
                IARG_ADDRINT, (ADDRINT)config,
                IARG_END);
    }

    if (INS_RegWContain(ins, REG_STACK_PTR)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)hdlr_stack_ptr_write_before,
                IARG_REG_VALUE, REG_INST_PTR,
                IARG_REG_VALUE, REG_STACK_PTR,
                IARG_END);
        if (INS_IsValidForIpointAfter(ins)) {
            INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)hdlr_stack_ptr_write_after,
                    IARG_REG_VALUE, REG_INST_PTR,
                    IARG_REG_VALUE, REG_STACK_PTR,
                    IARG_END);
        }
    }

    if (INS_IsMemoryRead(ins)) {
        for (UINT32 i = 0; i < INS_MemoryOperandCount(ins); i++) {
            if (INS_MemoryOperandIsRead(ins, i)) {
                memaccess_type = 0;
                if (INS_MemoryBaseReg(ins) != REG_INVALID()) {
                    memaccess_type = memaccess_type | MEMACCESS_BASE_REG_USED;
                    if (INS_MemoryIndexReg(ins) != REG_INVALID()) {
                        memaccess_type = memaccess_type | MEMACCESS_INDEX_REG_USED;
                        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)hdlr_memread,
                                IARG_UINT32, memaccess_type,
                                IARG_INST_PTR,
                                IARG_MEMORYREAD_EA,
                                IARG_REG_VALUE, INS_MemoryBaseReg(ins),
                                IARG_REG_VALUE, INS_MemoryIndexReg(ins),
                                IARG_UINT32, INS_MemoryDisplacement(ins),
                                IARG_UINT32, INS_MemoryOperandSize(ins, i),
                                IARG_END);
                    } else {
                        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)hdlr_memread,
                                IARG_UINT32, memaccess_type,
                                IARG_INST_PTR,
                                IARG_MEMORYREAD_EA,
                                IARG_REG_VALUE, INS_MemoryBaseReg(ins),
                                IARG_UINT32, 0,
                                IARG_UINT32, INS_MemoryDisplacement(ins),
                                IARG_UINT32, INS_MemoryOperandSize(ins, i),
                                IARG_END);
                    }
                } else {
                    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)hdlr_memread,
                            IARG_UINT32, memaccess_type,
                            IARG_INST_PTR,
                            IARG_MEMORYREAD_EA,
                            IARG_UINT32, 0,
                            IARG_UINT32, 0,
                            IARG_UINT32, INS_MemoryDisplacement(ins),
                            IARG_UINT32, INS_MemoryOperandSize(ins, i),
                            IARG_END);
                }
            }
        }
    }

    if (INS_IsMemoryWrite(ins) && INS_IsValidForIpointAfter(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)hdlr_memwrite_before,
                IARG_MEMORYWRITE_EA,
                IARG_END);

        for (UINT32 i = 0; i < INS_MemoryOperandCount(ins); i++) {
            if (INS_MemoryOperandIsWritten(ins, i)) {
                memaccess_type = 0;
                if (INS_MemoryBaseReg(ins) != REG_INVALID()) {
                    memaccess_type = memaccess_type | MEMACCESS_BASE_REG_USED;
                    if (INS_MemoryIndexReg(ins) != REG_INVALID()) {
                        memaccess_type = memaccess_type | MEMACCESS_INDEX_REG_USED;
                        INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)hdlr_memwrite_after,
                                IARG_UINT32, memaccess_type,
                                IARG_INST_PTR,
                                IARG_ADDRINT, 0,
                                IARG_REG_VALUE, INS_MemoryBaseReg(ins),
                                IARG_REG_VALUE, INS_MemoryIndexReg(ins),
                                IARG_UINT32, INS_MemoryDisplacement(ins),
                                IARG_UINT32, INS_MemoryOperandSize(ins, i),
                                IARG_END);
                    } else {
                        INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)hdlr_memwrite_after,
                                IARG_UINT32, memaccess_type,
                                IARG_INST_PTR,
                                IARG_ADDRINT, 0,
                                IARG_REG_VALUE, INS_MemoryBaseReg(ins),
                                IARG_UINT32, 0,
                                IARG_UINT32, INS_MemoryDisplacement(ins),
                                IARG_UINT32, INS_MemoryOperandSize(ins, i),
                                IARG_END);
                    }
                } else {
                    INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)hdlr_memwrite_after,
                            IARG_UINT32, memaccess_type,
                            IARG_INST_PTR,
                            IARG_ADDRINT, 0,
                            IARG_UINT32, 0,
                            IARG_UINT32, 0,
                            IARG_UINT32, INS_MemoryDisplacement(ins),
                            IARG_UINT32, INS_MemoryOperandSize(ins, i),
                            IARG_END);
                }
            }
        }
    }
}

int main(int argc, char *argv[]) {
    PIN_InitSymbols();
    PIN_InitLock(&lock);

    if (unlikely(PIN_Init(argc, argv))) {
        std::cerr
            << "Sth error in PIN_Init. Plz use the right command line options."
            << std::endl;
        return -1;
    }

    if (unlikely(libdft_init() != 0)) {
        std::cerr << "Sth error libdft_init." << std::endl;
        return -1;
    }

    std::string config_file_name = KnobConfigFile.Value();
    if (config_file_name.empty()) {
        std::cout << "[-] Error: No config file specified." << std::endl;
        exit(-1);
    }
    
    std::cout << "[+] Config file: " << config_file_name << endl;

    std::string config_string = read_file(config_file_name);
    print_config_string(config_string);

    Config *config;
    config = parse_config(config_string);
    if (!is_config_valid(*config)) {
        std::cout << "Error: Invalid config." << std::endl;
        exit(-1);
    }
    print_config(*config);

    std::string output_file_name = KnobOutputFile.Value();
    if (!output_file_name.empty()) {
        std::cout << "[+] Output file: " << output_file_name << endl;
        out = new std::ofstream(output_file_name.c_str());
    }

    IMG_AddInstrumentFunction(Image, config);
    INS_AddInstrumentFunction(Ins, config);

    PIN_StartProgram();

    return 0;
}