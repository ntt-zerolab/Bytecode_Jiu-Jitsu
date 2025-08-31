#include "log.h"


extern std::ostream *out;
extern BOOL exec_context_is_user_script;
extern ADDRINT current_stack_ptr;
extern ADDRINT memwrite_addr;
extern ADDRINT target_image_base;
extern ADDRINT target_image_end;


VOID log_stack(ADDRINT insn_ptr, ADDRINT stack_ptr)
{
    if (!exec_context_is_user_script)
        return;
    if (insn_ptr < target_image_base || insn_ptr > target_image_end)
        return;

    PIN_LockClient();

    current_stack_ptr = stack_ptr;

    PIN_UnlockClient();
}

VOID log_memaccess(ADDRINT rw_type, uint32_t memaccess_type, ADDRINT insn_ptr, ADDRINT target_addr, ADDRINT base_addr, ADDRINT index, ADDRINT disp, ADDRINT size)
{
    PIN_LockClient();

    if (insn_ptr < target_image_base || insn_ptr > target_image_end) {
        PIN_UnlockClient();
        return;
    }

    string rw;
    if (rw_type == MEMACCESS_READ) {
        rw = "read";
    } else if (rw_type == MEMACCESS_WRITE) {
        rw = "write";
        target_addr = memwrite_addr;
    }

    uint8_t *buf;
    buf = new uint8_t[size];
    memset(buf, 0x0, size);
    PIN_SafeCopy(buf, (const VOID *)target_addr, size);

    *out << "trace: memaccess, type: "
         << rw
         << ", ip: "
         << (void *)insn_ptr
         << ", target: "
         << (void *)target_addr;
    if (memaccess_type & MEMACCESS_BASE_REG_USED) {
        * out << ", base: "
              << (void *)base_addr;
    }
    if (memaccess_type & MEMACCESS_INDEX_REG_USED) {
        *out << ", index: "
             << std::dec
             << index;
    }
    if (disp != 0) {
        *out << ", disp: 0x"
             << std::hex
             << disp;
    }
    *out << ", size: "
         << std::dec
         << size
         << ", value: ";
    switch (size) {
        case 1:
            *out << "0x"
                << std::setw(2) << std::setfill('0') << std::hex
                << int(*buf);
            break;
        case 2:
            *out << "0x"
                << std::setw(4) << std::setfill('0') << std::hex
                << *(uint16_t *)buf;
            break;
        case 4:
            *out << "0x"
                << std::setw(8) << std::setfill('0') << std::hex
                << *(uint32_t *)buf;
            break;
        case 8:
            *out << "0x"
                << std::setw(16) << std::setfill('0') << std::hex
                << *(uint64_t *)buf;
            break;
        case 16:
            *out << "0x"
                << std::setw(32) << std::setfill('0') << std::hex
                << *(uint64_t *)buf
                << *(uint64_t *)(buf + 8);
            break;
        case 32:
            *out << "0x"
                << std::setw(32) << std::setfill('0') << std::hex
                << *(uint64_t *)buf
                << *(uint64_t *)(buf + 8)
                << *(uint64_t *)(buf + 16)
                << *(uint64_t *)(buf + 24)
                << *(uint64_t *)(buf + 32);
            break;
        default:
            *out << (char *)buf;
            break;
    }
    *out << endl;

    delete[] buf;
    memwrite_addr = 0x0;

    PIN_UnlockClient();
}