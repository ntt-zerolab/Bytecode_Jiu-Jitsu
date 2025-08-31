#!/usr/bin/env python

from logproc import *
from tree import *
import logging

logging.basicConfig(format='[+] %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)


class Struct(object):
    def __init__(self, base, offset, size, index=None):
        self.base = base
        self.member = []
        if index is None:
            self.member.append({'offset': offset, 'size': size})
        else:
            self.member.append({'offset': offset, 'size': size, 'index': [index]})

    def __str__(self):
        result = 'base: {}\n'.format(hex(self.base))
        for member in self.member:
            if 'index' in member.keys():
                result += '{} {} {}\n'.format(hex(member['offset']), member['size'], member['index'])
            else:
                result += '{} {}\n'.format(hex(member['offset']), member['size'])
        return result
    
    def sort_member(self):
        self.member = sorted(self.member, key=lambda x: x['offset'])
    
    def add_member(self, offset, size, index=None):
        found = False
        for member in self.member:
            if member['offset'] == offset:
                if index is not None:
                    # member is array
                    if 'index' in member.keys():
                        if index not in member['index']:
                            member['index'].append(index)
                    else:
                        # TODO: investigate why this happens
                        member['index'] = [index]
                found = True
                break
        if not found:
            if index is None:
                # member is not array
                self.member.append({'offset': offset, 'size': size})
            else:
                # member is array
                self.member.append({'offset': offset, 'size': size, 'index': [index]})
            self.sort_member()

class Array(object):
    def __init__(self, base, index, size):
        self.base = base
        self.index = [index]
        self.size = size
        self.elem_struct = {}

    def __str__(self):
        result = 'base: {}\n'.format(hex(self.base))
        result += 'size: {}\n'.format(self.size)
        for index in self.index:
            result += '{}\n'.format(index)
        return result
    
    def sort_index(self):
        self.index = sorted(self.index)
    
    def add_index(self, index):
        self.index.append(index)
        self.index = list(set(self.index))
        self.sort_index()

    def add_elem_struct(self, structs, base):
        for struct in structs:
            if True:
                self.elem_struct.append(struct)

class Reference(object):
    def __init__(self):
        self.start_reg = None
        self.ref_offsets = []

    def __str__(self):
        string = self.start_reg.upper()
        for idx, offset in enumerate(self.ref_offsets):
            if isinstance(offset, dict):
                string += ' +{} (Array: elem size {})'.format(hex(offset['offset']), offset['size'])
            else:
                string += ' +{}'.format(hex(offset))

            if idx != len(self.ref_offsets) - 1:
                string += ' ->'

        return string
    
    def add_start_reg(self, reg):
        self.start_reg = reg

    def add_struct_ref(self, offset):
        self.ref_offsets.append(offset)

    def add_array_ref(self, offset, elem_size):
        self.ref_offsets.append({'offset': offset, 'size': elem_size})

def build_struct(memaccess_log):
    structs = []

    for logline in memaccess_log:
        base = logline['base']

        if 'disp' in logline.keys():
            disp = logline['disp']
            if disp != 0:
                size = logline['size']
                if 'index' in logline.keys():
                    index = logline['index']
                else:
                    index = None

                found = False
                for struct in structs:
                    if struct.base == base:
                        if index is None:
                            struct.add_member(disp, size)
                        else:
                            struct.add_member(disp, size, index)
                        break
                if not found:
                    if index is None:
                        structs.append(Struct(base, disp, size))
                    else:
                        structs.append(Struct(base, disp, size, index))

    return structs

def build_array(memaccess_log):
    arrays = []

    for logline in memaccess_log:
        if 'index' in logline.keys():
            index = logline['index']
            base = logline['base']
            size = logline['size']
            found = False
            for array in arrays:
                if array.base == base:
                    array.add_index(index)
                    found = True
                    break
            if not found:
                arrays.append(Array(base, index, size))

    return arrays

def find_struct(structs, addr):
    for struct in structs:
        for member in struct.member:
            if struct.base + member['offset'] == addr:
                return struct, member['offset']
            if 'index' in member.keys():
                for index in member['index']:
                    if struct.base + member['offset'] + index * member['size'] == addr:
                        return struct, member['offset']
            
        if struct.base == addr:
            return struct, 0
            
    return None

def find_array(arrays, addr):
    for array in arrays:
        for index in array.index:
            if array.base + index * array.size == addr:
                return array, index

        if array.base == addr:
            print('Target: {}'.format(hex(addr)))
            print('Found array base: {}'.format(hex(array.base)))
            print('Found index: 0')
            return array, 0
            
    return None

def build_struct_tree(structs, taint_var_log, start_addr):
    tree = []
    exploration_stack = []
    current_node_id = 0

    root = Node()
    root.addr = start_addr
    found = find_struct(structs, start_addr)
    if found is not None:
        root.struct = found[0]
        root.offset = found[1]
        logger.info('Found struct: {}'.format(found[0]))
        logger.info('Found offset: {}'.format(hex(found[1])))
    root.val = get_var_val(taint_var_log, start_addr)
    root.size = get_var_size(taint_var_log, start_addr)
    tree.append(root)

    exploration_stack.append(current_node_id)
    while len(exploration_stack) != 0:
        logger.info('Exploration stack: {}'.format(exploration_stack))
        current_node_id = exploration_stack.pop(-1)
        current_node = tree[current_node_id]
        found = find_struct(structs, current_node.addr)
        if found is not None:
            current_node.struct = found[0]
        else:
            print('{} not found'.format(current_node.addr))
            continue

        addrs = get_var_addr(taint_var_log, current_node.struct.base)
        for addr in addrs:
            new_node_id = len(tree)
            node = Node()
            node.id = new_node_id
            node.parent = current_node_id
            node.childs = []
            node.addr = addr
            found = find_struct(structs, addr)
            if found is not None:
                node.struct = found[0]
                node.offset = found[1]
                print(found[0], found[1])
            else:
                print('Struct base for {} not found'.format(hex(addr)))
                continue
            node.val = get_var_val(taint_var_log, addr)
            node.size = get_var_size(taint_var_log, addr)
            tree.append(node)
            current_node.childs.append(new_node_id)
            exploration_stack.append(new_node_id)

    return tree

def backtrack(tree, from_node_id):
    path = []

    node_id = from_node_id
    while node_id != -1:
        path.append(tree[node_id])
        node_id = tree[node_id].parent

    return path

def get_struct_ref_path(tree, addr):
    for node in tree:
        if node.struct.base == addr:
            return backtrack(tree, node.id)
        
def diff_ref_path(path1, path2):
    for (node1, node2) in zip(path1, path2):
        if node1.addr == node2.addr:
            print(hex(node1.addr))
        else:
            print(hex(node1.addr), hex(node2.addr))

def build_ref_info(struct_tree, ref_path, reg_values):
    ref = Reference()

    first_node = ref_path[0]
    for reg, val in reg_values.items():
        if ((first_node.struct is None and first_node.addr == val)
                or (first_node.struct is not None and first_node.struct.base == val)):
            ref.add_start_reg(reg)

    for node in ref_path:
        struct = get_struct(struct_tree, node.addr)

        for member in struct.member:
            if 'index' in member.keys():
                for index in member['index']:
                    if node.offset == member['offset'] + member['size'] * index:
                        ref.add_array_ref(member['offset'], member['size'])
            elif node.offset == member['offset']:
                ref.add_struct_ref(member['offset'])

    return ref

def get_struct(struct_tree, addr):
    for node in struct_tree:
        if node.addr == addr:
            return node.struct
        
    return None