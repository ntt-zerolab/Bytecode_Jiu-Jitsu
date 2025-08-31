#!/usr/bin/env python

from logproc import *
import re

def parse_taint_log(log_content):
    # TODO: fix a problem that this pattern cannot find the line below
    # b'trace: memtaint, addr: 0x00007fe66ac977f9, tag: {(2, 3) }, byte: 0x0a, char: '
    pattern_memtaint = b'trace: (?P<trace>memtaint), addr: (?P<addr>0x[0-9a-f]+), tag: (?P<tag>\{.+\}), byte: (?P<byte>0x[0-9a-f]{2}), char: (?P<char>.?)'
    pattern_reg = b'trace: (?P<trace>reg), reg: (?P<reg>.+), val: (?P<val>0x[0-9a-f]+)'
    pattern_stack = b'trace: (?P<trace>stack), stack ptr: (?P<stack_ptr>0x[0-9a-f]+)'

    p_memtaint = re.compile(pattern_memtaint, re.DOTALL)
    p_reg = re.compile(pattern_reg)
    p_stack = re.compile(pattern_stack)

    taint_log = []
    for line in log_content.split(b'\n'):
        logline = {}

        m = p_memtaint.search(line)
        if m is not None:
            try:
                logline['trace'] = m['trace'].decode('utf-8')
                logline['addr'] = int(m['addr'], 16)
                logline['tag'] = m['tag'].decode('utf-8')        # need consideration
                logline['byte'] = int(m['byte'], 16)
                logline['char'] = m['char']
                if len(logline['char']) == 0:
                    logline[['char']] = chr(logline['byte'])
                taint_log.append(logline)
            except Exception as e:
                print('could not serialize a log line {}: {}'.format(line, e))
            continue
        else:
            pos_memtaint = line.find(b'memtaint')
            pos_not_mapped = line.find(b'not mapped')
            if pos_memtaint != -1 and pos_not_mapped == -1:
                print('could not parse a log line {}'.format(line))

        m = p_reg.search(line)
        if m is not None:
            try:
                logline['trace'] = m['trace'].decode('utf-8')
                logline['reg'] = m['reg'].decode('utf-8')
                logline['val'] = int(m['val'], 16)
                taint_log.append(logline)
            except Exception as e:
                print('could not serialize a log line {}: {}'.format(line, e))
            continue

        m = p_stack.search(line)
        if m is not None:
            try:
                logline['trace'] = m['trace'].decode('utf-8')
                logline['stack_ptr'] = int(m['stack_ptr'], 16)
                taint_log.append(logline)
            except Exception as e:
                print('could not serialize a log line {}: {}'.format(line, e))
            continue

    return taint_log

def parse_tainted_memaccess_log(log_content, log):
    pattern_memaccess = b'trace: (?P<trace>memaccess), type: (?P<type>read|write), ip: (?P<ip>0x[0-9a-f]+), target: (?P<target>0x[0-9a-f]+), (base: (?P<base>0x[0-9a-f]+), )?(index: (?P<index>[0-9]+), )?(disp: (?P<disp>0x[0-9a-f]+), )?size: (?P<size>[0-9]+), value: (?P<value>0x[0-9a-f]+)'
    p_memaccess = re.compile(pattern_memaccess)

    tainted_addrs = tuple(get_tainted_addrs(log))

    memaccess_log = []
    for line in log_content.split(b'\n'):
        logline = {}

        m = p_memaccess.search(line)
        if m is not None:
            target_addr = int(m['target'], 16)
            if target_addr in tainted_addrs:
                try:
                    logline['trace'] = m['trace'].decode('utf-8')
                    logline['type'] = m['type'].decode('utf-8')
                    logline['ip'] = int(m['ip'], 16)
                    logline['target'] = target_addr
                    if m['base'] is not None:
                        logline['base'] = int(m['base'], 16)
                    if m['index'] is not None:
                        logline['index'] = int(m['index'])
                    if m['disp'] is not None:
                        logline['disp'] = int(m['disp'], 16)
                    logline['size'] = int(m['size'])
                    logline['value'] = int(m['value'], 16)
                    memaccess_log.append(logline)
                except Exception as e:
                    print('could not serialize a log line {}: {}'.format(line, e))

    return memaccess_log

def parse_heap_alloc_log(log_content):
    pattern_heap_alloc = b'trace: (?P<trace>heap), type: (?P<type>alloc), addr: (?P<addr>0x[0-9a-f]+), size: (?P<size>[0-9]+)'

    p_heap_alloc = re.compile(pattern_heap_alloc)

    heap_alloc_log = []
    for line in log_content.split(b'\n'):
        logline = {}

        m = p_heap_alloc.search(line)
        if m is not None:
            try:
                logline['trace'] = m['trace'].decode('utf-8')
                logline['type'] = m['type'].decode('utf-8')
                logline['addr'] = int(m['addr'], 16)
                logline['size'] = int(m['size'])
                heap_alloc_log.append(logline)
            except Exception as e:
                print('could not serialize a log line {}: {}'.format(line, e))

    return heap_alloc_log