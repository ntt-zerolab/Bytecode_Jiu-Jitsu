import logging

logging.basicConfig(format='[+] %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)


def find_ascii_or_wide_substring(buf, target):
    target_ascii = target.encode('ascii')
    target_utf16le = target.encode('utf-16le')

    if isinstance(buf, str):
        buf_bytes = buf.encode('utf-8', errors='replace')
    else:
        buf_bytes = buf

    logger.debug('buf: {}'.format(buf_bytes))
    logger.debug('target (ASCII): {}'.format(target))
    logger.debug('target (UTF-16LE): {}'.format(target_utf16le))

    # ASCII search
    pos = buf_bytes.find(target_ascii)
    if pos != -1:
        return pos
    
    # UTF-16LE search
    pos = buf_bytes.find(target_utf16le)
    if pos != -1:
        return pos
    
    return None

def find_symtable_buf(heap_bufs, target_string):
    found_bufs = []

    for i, buf in enumerate(heap_bufs):
        pos = find_ascii_or_wide_substring(buf['bytes'], target_string)
        if pos is not None:
            found_bufs.append(buf)

    return found_bufs