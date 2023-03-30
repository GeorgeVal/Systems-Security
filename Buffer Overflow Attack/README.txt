Georgios Valavanis 

First step: Find where RIP and big_boy_buffer, buffer are located.
In order to find rip we need to find where buffer is located.
Running disas vuln using gdb outputs:
   0x00000000004011ee <+0>:	endbr64 
   0x00000000004011f2 <+4>:	push   %rbp
   0x00000000004011f3 <+5>:	mov    %rsp,%rbp
   0x00000000004011f6 <+8>:	sub    $0x70,%rsp
   0x00000000004011fa <+12>:	movq   $0x0,-0x70(%rbp)
   0x0000000000401202 <+20>:	movq   $0x0,-0x68(%rbp)
   
Before the movq commands a sub is used to allocate memory for the buffer and 0x70 means that the buffer is approx. 0x70 = 112 bytes away from rip.

Because of enviroment variables the true distance won't be 112 bytes but larger. In order to find out we run the program with dgb and try writing 113 bytes on buffer, and check the address on the error message. If it isn't overwritten we try writing 114 bytes, etc.

After some tries the rip was fully overwritten after writing 112+11 = 123 characters (bytes).

Now we know that 123 bytes are needed to fully overwrite the RIP register.

We make our payload 120 bytes long and add the return address on last 3 bytes.

We create a "slope" of No-ops at the first addresses of the buffer that lead to the shellcode.
In order to be certain that the RIP is overwritten with the big_boy_buffer's return address we 
write its return address on the payload multiple times (10).

We notice that when executing cat payload.bin | ./bof the new shell is opened and terminated right 
after, because the pipe closes (the shell has no input). In order to keep the pipe open, so that 
the shell is kept alive we execute instead (cat payload.bin ; cat) | ./bof. The 2nd cat keeps the 
shell process alive, because it waits for stdin input (pipe remains open).

When executing the above line you need to hit enter when the program is prompt so that the payload 
file write the payload to buffer.
