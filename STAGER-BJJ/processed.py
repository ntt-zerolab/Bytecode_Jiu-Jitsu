#!/usr/bin/env python

import json

def save_proc_taint_log_to_json(taint_log, proc_taint_log_json_file):
    taint_log_for_json = []
    for logline in taint_log:
        if logline['trace'] == 'memtaint':
            taint_log_for_json.append({
                'trace': logline['trace'],
                'addr': logline['addr'],
                'tag': logline['tag'],
                'byte': logline['byte'],
                'char': ''
            })
        else:
            taint_log_for_json.append(logline)
    save_proc_log_to_json(taint_log_for_json, proc_taint_log_json_file)

def load_proc_taint_log_from_json(proc_taint_log_json_file):
    taint_log = load_proc_log_from_json(proc_taint_log_json_file)
    for i in range(len(taint_log)):
        if taint_log[i]['trace'] == 'memtaint':
            taint_log[i]['char'] = taint_log[i]['byte'].to_bytes(1, 'little')
    return taint_log

def save_proc_taint_var_log_to_json(taint_var_log, proc_taint_var_log_json_file):
    taint_var_log_for_json = []
    for logline in taint_var_log:
        if logline['trace'] == 'memtaint_var':
            taint_var_log_for_json.append({
                'trace': logline['trace'],
                'addr': logline['addr'],
                'tag': logline['tag'],
                'size': logline['size'],
                'bytes': logline['bytes'],
                'chars': ''
            })
        else:
            taint_var_log_for_json.append(logline)
    save_proc_log_to_json(taint_var_log_for_json, proc_taint_var_log_json_file)

def load_proc_taint_var_log_from_json(proc_taint_var_log_json_file):
    taint_var_log = load_proc_log_from_json(proc_taint_var_log_json_file)
    for i in range(len(taint_var_log)):
        if taint_var_log[i]['trace'] == 'memtaint_var':
            taint_var_log[i]['chars'] = taint_var_log[i]['bytes'].to_bytes(taint_var_log[i]['size'], 'little')
    return taint_var_log

def save_proc_log_to_json(proc_log, proc_log_json_file):
    with open(proc_log_json_file, 'w') as f:
        f.write(json.dumps(proc_log))

def load_proc_log_from_json(proc_log_json_file):
    with open(proc_log_json_file, 'r') as f:
        return json.loads(f.read())