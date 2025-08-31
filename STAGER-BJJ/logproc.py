#!/usr/bin/env python

import copy
import logging
import sys

logging.basicConfig(format='[+] %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

def get_init_mem_value(memaccess_log, addr):
    for logline in memaccess_log:
        if logline['target'] == addr:
            if logline['type'] == 'read':
                return logline['value']
            elif logline['type'] == 'write':
                return None
            else:
                logger.warning('Unknown memaccess type: {}'.format(logline))
    return None

def get_stack_ptr(log):
    for logline in log:
        if logline['trace'] == 'stack':
            return logline['stack_ptr']
    return None

def get_reg_values(log):
    reg = {}
    for logline in log:
        if logline['trace'] == 'reg':
            try:
                reg[logline['reg']] = logline['val']
            except Exception as e:
                logger.error('Could not get reg value: {}'.format(e))
                sys.exit()

        if len(reg.keys()) == 2:
            return reg
    return None

def get_bytes(log, addr, size):
    bytes_str = ''
    for i in range(size):
        for logline in log:
            if logline['trace'] == 'memtaint' and logline['addr'] == addr + 7 - i:
                bytes_str += '{:02x}'.format(logline['byte'])
                break
    return bytes_str

def get_tainted_addrs(log):
    tainted_addrs = []
    for logline in log:
        if logline['trace'] in ('memtaint', 'memtaint_consolidated', 'struct'):
            tainted_addrs.append(logline['addr'])

    return tainted_addrs

def get_var_size(memaccess_log, addr):
    for logline in memaccess_log:
        if logline['target'] == addr:
            return logline['size']
    return None

def log_has_addr(log, addr):
    for logline in log:
        if logline['addr'] == addr:
            return True
    return False

def get_struct(struct_log, addr):
    for logline in struct_log:
        if logline['addr'] == addr:
            return logline
    return False

def struct_has_offset(struct, offset):
    return offset in struct['offsets']

def get_struct_base(memaccess_log, addr):
    for logline in memaccess_log:
        if logline['target'] == addr:
            return logline['base']
    return None

def get_var_addr(var_log, val):
    addrs = []

    for logline in var_log:
        if logline['addr'] is not None and logline['bytes'] is not None:
            if logline['bytes'] == val:
                addrs.append(logline['addr'])

    return addrs

def get_var_val(var_log, addr):
    for logline in var_log:
        if logline['addr'] == addr:
            return logline['bytes']
    return None

def create_addr_to_size_map(memaccess_log):
    addr_to_size_map = {}
    for logline in memaccess_log:
        addr = logline['target']
        size = logline['size']
        addr_to_size_map[addr] = size

    return addr_to_size_map

def get_var_size(var_log, addr):
    for logline in var_log:
        if ((logline['trace'] == 'memaccess' and logline['target'] == addr)
                or logline['trace'] == 'memtaint_var' and logline['addr'] == addr):
            return logline['size']
    return None

def get_var_size_from_map(addr_to_size_map, addr):
    if addr in addr_to_size_map.keys():
        return addr_to_size_map[addr]
    else:
        None

def get_heap_start_addrs(heap_alloc_log):
    return [x['addr'] for x in heap_alloc_log]

def create_addr_to_tainted_byte_map(taint_log):
    addr_to_tainted_byte_map = {}
    for logline in taint_log:
        if logline['trace'] == 'memtaint':
            addr = logline['addr']
            byte = logline['char']
            addr_to_tainted_byte_map[addr] = byte

    return addr_to_tainted_byte_map

def get_tainted_byte(addr_to_tainted_byte_map, addr):
    if addr in addr_to_tainted_byte_map.keys():
        return addr_to_tainted_byte_map[addr]
    else:
        None

def generate_init_var_log(var_log, memaccess_log):
    init_var_log = copy.deepcopy(var_log)

    for i in range(len(var_log)):
        found = False
        for logline in memaccess_log:
            if init_var_log[i]['addr'] == logline['target']:
                if logline['type'] == 'read':
                    init_var_log[i]['bytes'] = logline['value']
                    init_var_log[i]['size'] = logline['size']
                    init_var_log[i]['chars'] = init_var_log[i]['bytes'].to_bytes(init_var_log[i]['size'], 'little')
                    found = True
                elif logline['type'] == 'write':
                    init_var_log[i]['bytes'] = None
                    init_var_log[i]['chars'] = None
                    found = True
                else:
                    logger.warning('Unknown memaccess type: {}'.format(logline))
                break
        if not found:
            logger.warning('Could not find target addr {}'.format(hex(var_log[i]['addr'])))
    return init_var_log

def consolidate_vars_into_struct(taint_var_log, memaccess_log):
    taint_struct_log = []

    for logline in taint_var_log:
        if logline['trace'] == 'memtaint_var':
            addr = logline['addr']
            struct_base = get_struct_base(memaccess_log, addr)
            struct_offset = addr - struct_base
            if log_has_addr(taint_struct_log, struct_base):
                for struct in taint_struct_log:
                    if struct['addr'] == struct_base and struct_offset not in struct['offsets']:
                        struct['offsets'].append(struct_offset)
                        struct['tag'].append(logline['tag'])
                        struct['size'].append(logline['size'])
                        struct['bytes'].append(logline['bytes'])
                        struct['chars'].append(logline['chars'])
            else:
                taint_struct_log.append({
                    'trace': 'memtaint_struct',
                    'addr': struct_base,
                    'offsets': [struct_offset],
                    'tag': [logline['tag']],
                    'size': [logline['size']],
                    'bytes': [logline['bytes']],
                    'chars': [logline['chars']]
                })

    return taint_struct_log

def consolidate_bytes(taint_log, index, addr, size):
    bytes_count = 0
    consolidate = False

    consolidated_bytes = 0
    i = index - size
    while i <= len(taint_log):
        logline = taint_log[i]
        i = i + 1
        if logline['trace'] == 'memtaint' and logline['addr'] == addr:
            consolidate = True

        if consolidate:
            consolidated_bytes = consolidated_bytes + (logline['byte'] << (8 * bytes_count))
            bytes_count = bytes_count + 1

            if bytes_count == size:
                return consolidated_bytes
            
    return None

def consolidate_chars(taint_log, index, addr, size):
    chars_count = 0
    consolidate = False

    consolidated_chars = b''

    i = index - size
    while i <= len(taint_log):
        logline = taint_log[i]
        i = i + 1
        if logline['trace'] == 'memtaint' and logline['addr'] == addr:
            consolidate = True

        if consolidate:
            consolidated_chars = consolidated_chars + logline['char']
            chars_count = chars_count + 1

            if chars_count == size:
                return consolidated_chars
            
    return None

def consolidate_bytes_into_var(taint_log, memaccess_log):
    taint_var_log = []
    prev_addr = None
    prev_tag = None
    start_addr = None

    addr_to_size_map = create_addr_to_size_map(memaccess_log)

    cont_bytes_count = 1
    for index, logline in enumerate(taint_log):
        if logline['trace'] == 'memtaint':
            current_addr = logline['addr']
            current_tag = logline['tag']

            if prev_addr is None:
                start_addr = current_addr
                size = get_var_size_from_map(addr_to_size_map, start_addr)
                if size is None:
                    logger.debug('Could not find memaccess at {}.'.format(hex(start_addr)))
                    continue
                prev_addr = current_addr
                prev_tag = current_tag
                continue

            if current_addr == prev_addr + 1 and current_tag == prev_tag and cont_bytes_count < size:
                cont_bytes_count = cont_bytes_count + 1
            else:
                consolidated_bytes = consolidate_bytes(taint_log, index, start_addr, cont_bytes_count)
                consolidated_chars = consolidate_chars(taint_log, index, start_addr, cont_bytes_count)
                if size != 0:
                    taint_var_log.append({
                        'trace': 'memtaint_var',
                        'addr': start_addr,
                        'tag': prev_tag,
                        'size': cont_bytes_count,
                        'bytes': consolidated_bytes,
                        'chars': consolidated_chars
                    })
                start_addr = current_addr
                size = get_var_size_from_map(addr_to_size_map, start_addr)
                if size is None:
                    # The case in which over-tainting occurs
                    # A base register is always 8-bytes but the propagation target register is not
                    size = 0
                cont_bytes_count = 1

            prev_addr = current_addr
            prev_tag = current_tag

    return taint_var_log

def consolidate_bytes_into_buf(taint_log, heap_alloc_log):
    consolidated_buf = []

    heap_start_addrs = get_heap_start_addrs(heap_alloc_log)

    prev_addr = None
    consolidated_bytes = b''
    for logline in taint_log:
        if logline['trace'] == 'memtaint':
            current_addr = logline['addr']
            current_byte = logline['char']

            if prev_addr is None:
                if current_addr in heap_start_addrs:
                    buf_base = current_addr
                    consolidated_bytes = consolidated_bytes + current_byte
                    prev_addr = current_addr
            else:
                if current_addr == prev_addr + 1 and current_addr not in heap_start_addrs:
                    consolidated_bytes = consolidated_bytes + current_byte
                    prev_addr = current_addr
                else:
                    buf = {}
                    buf['base'] = buf_base
                    buf['bytes'] = consolidated_bytes
                    buf['size'] = current_addr - buf_base
                    consolidated_buf.append(buf)
                    if current_addr in heap_start_addrs:
                        buf_base = current_addr
                        consolidated_bytes = current_byte
                        prev_addr = current_addr
                    else:
                        prev_addr = None
                        consolidated_bytes = b''

    return consolidated_buf

def reconstruct_heap_buf(taint_log, heap_alloc_log):
    bufs = []

    addr_to_tainted_byte_map = create_addr_to_tainted_byte_map(taint_log)

    for logline in heap_alloc_log:
        heap_base_addr = logline['addr']
        heap_size = logline['size']

        reconstructed_bytes = b''
        addr = heap_base_addr
        while addr <= heap_base_addr + heap_size:
            tainted_byte = get_tainted_byte(addr_to_tainted_byte_map, addr)
            if tainted_byte is not None:
                reconstructed_bytes += tainted_byte
            else:
                reconstructed_bytes += b'\x00'
            addr = addr + 1

        buf = {}
        buf['base'] = heap_base_addr
        buf['bytes'] = reconstructed_bytes
        buf['size'] = heap_size
        bufs.append(buf)

    return bufs

def generate_struct_bytes(taint_struct_log, addr):
    for logline in taint_struct_log:
        if logline['addr'] == addr:
            struct_bytes = b'\x00' * (logline['offsets'][-1] + logline['size'][-1])
            for i in range(len(logline['offsets'])):
                if logline['chars'][i] is not None:
                    start = logline['offsets'][i]
                    end = logline['offsets'][i] + logline['size'][i]
                    struct_bytes = struct_bytes[:start] + logline['chars'][i] + struct_bytes[end:]
    return struct_bytes

