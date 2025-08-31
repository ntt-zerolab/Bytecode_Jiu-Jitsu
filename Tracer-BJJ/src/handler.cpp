#include "handler.h"


extern std::ostream *out;

// extern const ptrdiff_t offset_vpc_read;
// const ptrdiff_t offset_vpc_read = 0x305444;
extern PIN_LOCK lock;
extern ADDRINT target_image_base;
extern ADDRINT memwrite_addr;
UINT64 vm_insn_id = 0;
BOOL script_engine_vm_insns_are_skipped = false;
BOOL exec_context_is_user_script = false;
ADDRINT vpc;
ADDRINT obj1;
ADDRINT obj2;
ADDRINT ptr_obj1;
ADDRINT ptr_obj2;
ADDRINT current_stack_ptr = 0x0;


VOID hdlr_stack_ptr_write_before(ADDRINT insn_ptr, ADDRINT stack_ptr)
{
    log_stack(insn_ptr, stack_ptr);
}

VOID hdlr_stack_ptr_write_after(ADDRINT insn_ptr, ADDRINT stack_ptr)
{
    log_stack(insn_ptr, stack_ptr);
}

// VOID hdlr_memread(ADDRINT insn_ptr, ADDRINT target_addr, ADDRINT base_addr, ADDRINT size)
VOID hdlr_memread(uint32_t memaccess_type, ADDRINT insn_ptr, ADDRINT target_addr, ADDRINT base_addr, ADDRINT index, ADDRINT disp, ADDRINT size)
{
    if (!exec_context_is_user_script) return;
    // log_memaccess(MEMACCESS_READ, insn_ptr, target_addr, base_addr, size);
    log_memaccess(MEMACCESS_READ, memaccess_type, insn_ptr, target_addr, base_addr, index, disp, size);
}

VOID hdlr_memwrite_before(ADDRINT target_addr)
{
    if (!exec_context_is_user_script) return;
    memwrite_addr = target_addr;
}

// VOID hdlr_memwrite_after(ADDRINT insn_ptr, ADDRINT target_addr, ADDRINT base_addr, ADDRINT size)
VOID hdlr_memwrite_after(uint32_t memaccess_type, ADDRINT insn_ptr, ADDRINT target_addr, ADDRINT base_addr, ADDRINT index, ADDRINT disp, ADDRINT size)
{
    if (!exec_context_is_user_script) return;
    // log_memaccess(MEMACCESS_WRITE, insn_ptr, target_addr, base_addr, size);
    log_memaccess(MEMACCESS_WRITE, memaccess_type, insn_ptr, target_addr, base_addr, index, disp, size);
}

VOID hdlr_interp_func_before(THREADID tid, REG rdi, REG rsi, ADDRINT arg1, ADDRINT arg2) {
    ptr_obj1 = arg1;
    ptr_obj2 = arg2;
    tag_t t1, t2;

    if (script_engine_vm_insns_are_skipped)
        exec_context_is_user_script = true;

    if (!exec_context_is_user_script) return;

    *out << "trace: stack, stack ptr: 0x"
         << std::setw(REGISTER_WIDTH) << std::setfill('0') << std::hex
         << current_stack_ptr
         << endl;

    *out << "trace: reg, reg: "
         << REG_StringShort(rdi)
         << ", val: "
         << (void *)arg1
         << endl;

    *out << "trace: reg, reg: "
         << REG_StringShort(rsi)
         << ", val: "
         << (void *)arg2
         << endl;
 
    t1 = tag_alloc<tag_t>(1);
    t2 = tag_alloc<tag_t>(2);
    for (int i = 0; i < 8; i++) {
        tagmap_setb_reg(tid, REG_INDX(rdi), i, t1);
        tagmap_setb_reg(tid, REG_INDX(rsi), i, t2);
    }

    PIN_GetLock(&lock, 1);
    *out << "[Info] " << __FUNCTION__ << " start" << endl;
    print_rtag_gr64(out, tid, rdi, "[getb_reg] ");
    print_rtag_gr64(out, tid, rsi, "[getb_reg] ");
    *out << "[Info] " << __FUNCTION__ << " end" << endl;
    PIN_ReleaseLock(&lock);
}

VOID hdlr_interp_func_after(THREADID tid) {
    if (!exec_context_is_user_script) return;

    PIN_GetLock(&lock, 1);
    *out << "[Info] " << __FUNCTION__ << " start" << endl;
    tagmap_explore(out);
    rtag_explore(out, tid);

    // print_tag_qword(obj1, "Obj1.val");
    // print_tag_qword(obj2, "Obj2.val");
    // print_tag_qword(obj2 + 8, "Obj2.p_obj1");

    *out << "[Info] " << __FUNCTION__ << " end" << endl;
    PIN_ReleaseLock(&lock);
}

VOID hdlr_mov_stack_read_before(ADDRINT ip, ADDRINT target_addr, Config *config) {
    // if (ip == target_image_base + offset_vpc_read)
    if (ip == target_image_base + config->decoder_offset)
        vpc = target_addr;
}

VOID hdlr_mov_stack_read_after(ADDRINT ip, UINT32 vmop, Config *config) {
    // if (ip == target_image_base + offset_vpc_read) {
    if (ip == target_image_base + config->decoder_offset) {
        if (exec_context_is_user_script) {
            PIN_GetLock(&lock, 1);
            *out << "trace: vm, id: "
                 << std::dec
                 << vm_insn_id
                 << ", vpc: "
                 << (void *)vpc
                 << ", vmop: 0x"
                 << std::hex << std::setfill('0') << std::setw(2)
                 << vmop
                 << endl;
            PIN_ReleaseLock(&lock);
        }

        vm_insn_id++;
        if (vm_insn_id == 59423) script_engine_vm_insns_are_skipped = true;
    }
}
