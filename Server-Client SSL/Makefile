$CC = gcc
server: 
	$(CC) -Wall -o server server.c -L/usr/lib -lssl -lcrypto
client:
	$(CC) -Wall -o client client.c -L/usr/lib -lssl -lcrypto 
assign_2:
	$(CC)  -Wall -o server server.c -L/usr/lib -lssl -lcrypto
	$(CC)  -Wall -o client client.c -L/usr/lib -lssl -lcrypto  
clean_client:
	rm  client
clean_server:
	rm  server
clean:
	rm  client
	rm  server
