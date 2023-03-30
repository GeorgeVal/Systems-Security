#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#define FAIL    -1


// Create the SSL socket and intialize the socket address structure
int OpenListener(int port)
{
    int sd;
    struct sockaddr_in addr;
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 8) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}
int isRoot()
{
    if (getuid() != 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

SSL_CTX* InitServerCTX(void)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    method = TLS_server_method();  /* Create new server-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    //if client hasnt proper certificate, then verification fails
    SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,NULL);
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }
    return ctx;
}

//Loads server certificates and loads certificates of trusted CAs for client authentication.
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key and certificate mismatch\n");
        exit(-1);
    }

    // Load certificates of trusted Certificate Authorities (client.pem)
    if (SSL_CTX_load_verify_locations(ctx,"client.pem",NULL)<1) {
        printf("Error setting the verify locations.\n");
        exit(-1);
    }
    // Set CA list used for client authentication. 
    SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file("client.pem"));
}

void ShowCerts(SSL* ssl)
{
    X509 *cert;
    char *cert_line;
    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Client certificates:\n");
        cert_line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", cert_line);
        free(cert_line);
        cert_line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", cert_line);
        free(cert_line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}
void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{
    char buffer[2048] = {0};
    int sd, b_read;
    const char* ServerResponse="\n<Body>\n\t\t<Name>sousi.com</Name>\n\t\t<year>1.5</year>\n\t\t<BlogType>Embedede and c c++</BlogType>\n\t\t<Author>John Johny</Author>\n</Body>";
    sd = SSL_get_fd(ssl);  /* get socket connection */
    const char *cpValidMessage = "\n<Body>\n\t\t<User>Sousi</UserName>\n\t\t<Password>123</Password>\n</Body>";
    if ( SSL_accept(ssl) == FAIL || SSL_get_verify_result(ssl) != X509_V_OK) {    /* do SSL-protocol accept */
        printf("SSL Client Authentication error\n");
    }
    else
    { 
        /*Print out connection details*/
        printf("SSL connection on socket: %d,Protocol Version: %s, Cipher: %s\n",
        sd, SSL_get_version(ssl), SSL_get_cipher(ssl));

        ShowCerts(ssl);        /* get any certificates */
        b_read = SSL_read(ssl, buffer, sizeof(buffer)); /* get request */
        buffer[b_read] = '\0';
        printf("Client msg: \"%s\"\n", buffer);
        if ( b_read > 0 )
        {
            if(strcmp(cpValidMessage,buffer) == 0)
            {
                SSL_write(ssl, ServerResponse, strlen(ServerResponse)); /* send reply */
            }
            else
            {
                SSL_write(ssl, "Invalid Message", strlen("Invalid Message")); /* send reply */
            }
        }
        else
        {
            ERR_print_errors_fp(stderr);
        }
    }
    SSL_free(ssl);         /* release SSL state */
    close(sd);          /* close connection */
}
int main(int count, char *Argc[])
{
    //Only root user have the permsion to run the server
    if(!isRoot())
    {
        printf("This program must be run as root/sudo user!!");
        exit(-1);
    }
    if ( count != 2 )
    {
        printf("Usage: %s <portnum>\n", Argc[0]);
        exit(-1);
    }
    SSL_CTX *ctx;
    int server;
    char *portnum;
    // Initialize the SSL library
    SSL_library_init();
    portnum = Argc[1];
    ctx = InitServerCTX();        /* initialize SSL */
    LoadCertificates(ctx, "mycert.pem", "mycert.pem"); /* load certs */
    server = OpenListener(atoi(portnum));    /* create server socket */

    while (1)
    {
        SSL *ssl;
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        int client = accept(server, (struct sockaddr*)&addr, &addr_len);  /* accept connection as usual */
        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);              /* get new SSL state with context */
        SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
        Servlet(ssl);         /* service connection */

    }
    close(server);          /* close server socket */
    SSL_CTX_free(ctx);         /* release context */
}