#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#define FAIL    -1

int OpenConnection(const char *hostname, int port)
{
    if (!gethostbyname(hostname)){
        fprintf(stderr, "Invalid IP\n");
        exit(-1);
    }
    int sd;
    struct sockaddr_in addr;
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(gethostbyname(hostname)->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        fprintf(stderr, "Error opening connection on socket\n");
        exit(-1);
    }
    return sd;
}

SSL_CTX* InitCTX(void)
{
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    method = TLS_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }
    return ctx;
}

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
        fprintf(stderr, "Private key and certificate mismatch!\n");
        exit(-1);
    }
}
void ShowCerts(SSL* ssl)
{
    X509 *cert;
    char *cert_line;
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        cert_line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", cert_line);
        free(cert_line);       /* free the malloc'ed string */
        cert_line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", cert_line);
        free(cert_line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No client certificates configured.\n");
}
int main(int count, char *strings[])
{
    if ( count != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }
    SSL_library_init();
    SSL_CTX *ctx;
    SSL *ssl;
    int server;
    char buffer[2048];
    char acClientRequest[2048] = {0};
    int bytes;
    ctx = InitCTX();
    LoadCertificates(ctx, "client.pem", "client.pem");
    server = OpenConnection(strings[1], atoi(strings[2]));
    ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, server);    /* attach the socket descriptor */
    if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
        ERR_print_errors_fp(stderr);
    else
    {
        char acUsername[16] = {0};
        char acPassword[16] = {0};
        const char *cpRequestMessage = "\n<Body>\n\t\t<User>%s</UserName>\n\t\t<Password>%s</Password>\n</Body>";
        printf("Enter the User Name : ");
        scanf("%s",acUsername);
        printf("\n\nEnter the Password : ");
        scanf("%s",acPassword);
        sprintf(acClientRequest, cpRequestMessage, acUsername,acPassword);   /* construct reply */
        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);        /* get any certs */
        SSL_write(ssl,acClientRequest, strlen(acClientRequest));   /* encrypt & send message */
        bytes = SSL_read(ssl, buffer, sizeof(buffer)); /* get reply & decrypt */
        buffer[bytes] = 0;
        printf("Server Response: \"%s\"\n", buffer);
        SSL_free(ssl);        /* release connection state */
    }
    close(server);         /* close socket */
    SSL_CTX_free(ctx);        /* release context */
    return 0;
}