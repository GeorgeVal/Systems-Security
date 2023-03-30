$CC = gcc
dh_assign_1: 
	$(CC)  dh_assign_1.c -o  dh_assign_1 -lm
rsa_assign_1:
	$(CC)  rsa_assign_1.c -o  rsa_assign_1 -lgmp 
assign_1:
	$(CC)  dh_assign_1.c -o  dh_assign_1 -lm
	$(CC)  rsa_assign_1.c -o  rsa_assign_1 -lgmp 
dh_clean:
	rm  dh_assign_1
rsa_clean:
	rm  rsa_assign_1
clean:
	rm  dh_assign_1
	rm  rsa_assign_1
