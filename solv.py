#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF('PATH_TO_BINARY', checksec=False)
libc = elf.libc

context(terminal=['tmux', 'split-window', '-h'])
context.log_level = 'info'

gs = '''
continue
'''.format(**locals())

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process(elf.path, *a, **kw)

if __name__=='__main__':
    io = start()

    io.interactive()