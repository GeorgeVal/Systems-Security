OpenSSL version OpenSSL 1.0.2p  14 Aug 2018 (output of openssl version terminal command)

MakeFile execution:

-make server : makes server executable

-make client : makes client executable

-make assign_2 : makes both client and server executables

-clean_client : removes client executable

-clean_server : removes server executable

-clean: removes both executables

Explaining the command below:

○ openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout
mycert.pem -out mycert.pem

The req command primarily creates and processes certificate requests in PKCS#10 format. It can additionally create self signed certificates for use as root CAs for example.

The -x509 option is used for generating a self signed certificate request.

The -nodes option prohibits encryption of a private key (if created).

The -days option specifies the number of days to certify the certificate for (in our case its 365 days).

The -newkey option creates a new certificate request and a new private key. In our case
it generates an RSA key of 1024 bits in size.

The -keyout option specifies the filename to write the created private key to. In our case it is 
the mycert.pem file.

The -out option gives the filename to write the output (self-signed certificate and private RSA key in our case).

Answering Tool Questions:

First run the server. Example: sudo ./server 8082
a. Why should you use the sudo command?
b. What is the number 8082?

Sudo command is used to run the server as root user. The isRoot function in the server.c
prevents from running the server file without being a root user.

The number 8082 is the port number that the server uses.

Then run the client. Example: ./client 127.0.0.1 8082
a. What is 127.0.0.1?
b. What is 8082?

127.0.0.1 is the local host IP and 8082 is the port number.
(Local host ip can be found using ifconfig on a terminal)

Explaining the implementation:

The client and server files implement a secure server-client program using TLS1.2. In my implementation client authentication is obligatory. There is a client.pem file that is used for
the client authentication and certification.

You can comment the LoadCertificate function in client.c to see that the authentication fails.
Even if there is a certificate in client, if it is not the client.pem certificate authentication fails.

Explaining functions: 

- OpenConnection: Receives hostname , initializes the communication socket and connects to it.

- InitCTX: Initializes context, and defines TLS1.2 as its method.

- LoadCertificates: Loads certificates and private keys (client's or server's).
If server doesnt receive a client certificate from a trusted CA , client authentication fails and connection is stopped.

- ShowCerts: Shows certificates received from the other end (client receives server's certificates
and server receives client certificates)

- main (client):  initializes ssl library, context, and loads client certificate. Opens connection with socket and creates new SSL connection state. Attaches server socket descriptor with ssl connection. Initiates the handshake. If handshake is completed successfully then client sends request message to server and reads server response.

- Servlet: Gets socket connection and initiates SSL protocol accept. If accept fails program exits
Then socket, protocol version and cipher are printed to ensure everything is ok. Then server receives client certificate and prints it. Server awaits client request and responds to it depending on the contents of client request. 

- main (server): Checks if server is run by user with root privileges. Then the SSL library is initiated, the context and the server certificate is loaded. A server listening socket is created and binded to a port. Then connection with client is accepted and serviced.

