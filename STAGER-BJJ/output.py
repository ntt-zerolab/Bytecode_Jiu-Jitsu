import json

def dump_output_config(ref, config):
    output = {}

    if ref.start_reg == 'rdi':
        output['management_structure_index'] = 0
    elif ref.start_reg == 'rsi':
        output['management_structure_index'] = 1

    symbol_tables = []
    symbol_table = {}
    symbol_table['forward_link_offset'] = 0

    symbol_table['reference_offsets'] = []
    for offset in ref.ref_offsets:
        if isinstance(offset, dict):
            symbol_table['reference_offsets'].append(offset['offset'])
        else:
            symbol_table['reference_offsets'].append(offset)
    symbol_table['type'] = 2
    symbol_table['scope'] = 0
    symbol_tables.append(symbol_table)

    output['symbol_tables'] = symbol_tables

    return json.dumps(output, indent=4)