#!/usr/bin/env python

from logproc import *

def print_struct(log, addr, size, reg_val, tainted_addrs):
    print('')
    for i in range(size):
        if i % 8 == 0:
            bytes_str = get_bytes(log, addr + i, 8)
            bytes_int = int(bytes_str, 16)
            if bytes_int in reg_val.values():
                for reg, val in reg_val.items():
                    if bytes_int == val:
                        print('{:#018x}  {}\t{}'.format(addr + i, bytes_str, reg))
            elif bytes_int in tainted_addrs:
                print('{:#018x}  {}\t*'.format(addr + i, bytes_str))
            else:
                print('{:#018x}  {}'.format(addr + i, bytes_str))

def print_init_struct(memaccess_log, addr, size, reg_val, tainted_addrs):
    print('')
    print(size)
    for i in range(size):
        if i % 8 == 0:
            if size - i > 8:
                member_size = 8
            else:
                member_size = size - i
            val = get_init_mem_value(memaccess_log, addr + i)
            if val is None:
                print('{:#018x}  not assigned'.format(addr + i))
            else:
                fmt_str = '{addr:#018x}  {val:0{digit}x}'.format(addr=addr + i, digit=member_size * 2, val=val)
                if val == reg_val['rdi']:
                    fmt_str += '\trdi'
                elif val == reg_val['rsi']:
                    fmt_str += '\trsi'
                elif val in tainted_addrs:
                    fmt_str += '\t*'
                print(fmt_str)

def print_taint_src_reg_values(log):
    reg_values = get_reg_values(log)
    for reg, val in reg_values.items():
        print('{}: {:#018x}'.format(reg.upper(), val))

def print_node(node):
    print('ID: {}'.format(node.id))
    print('Parent: {}'.format(node.parent))
    print('Childs: {}'.format(node.childs))
    print('Address: {:#018x}'.format(node.addr))
    print('Value: {val:#0{digit}x}'.format(digit=node.size * 2 + 2, val=node.val))
    print('Size: {}'.format(node.size))
    print('Struct base: {:#018x}'.format(node.struct.base))
    print('Struct offset: {:#x}'.format(node.offset))