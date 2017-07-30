/*
** client.c -- a stream socket client demo
** $ make --file=mfc && ./client 127.0.0.1 5555
*/

#include <arpa/inet.h>
#include <errno.h>
#include <malloc.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#define FAIL -1

int OpenConnection(const char *hostname, int port)
{
	int sd;
	struct hostent *host;
	struct sockaddr_in addr;

	if ( (host = gethostbyname(hostname)) == NULL)
	{
		perror(hostname);
		abort();
	}
	sd = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = *(long*)(host->h_addr);
	if ( connect(sd, (const struct sockaddr *)&addr, sizeof(addr)) != 0)
	{
		close(sd);
		perror(hostname);
		abort();
	}
	return sd;
}

SSL_CTX* InitCTX(void)
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	SSL_library_init();
	OpenSSL_add_all_algorithms();				// Load & register all cryptos etc.
	SSL_load_error_strings();				// Load all error messages
	method = SSLv2_client_method();				// create new server-method instance
	ctx = SSL_CTX_new(method);				// creat new context from method
	if ( ctx == NULL )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}

void ShowCerts(SSL* ssl)
{
	X509 *cert;
	char *line;

	cert = SSL_get_peer_certificate(ssl);			// Get certificate (if available)
	if ( cert != NULL )
	{
		printf("Server certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);
		X509_free(cert);
	}
	else
		printf("No certificates.\n");
}

int main(int argc, char *argv[])
{
	SSL_CTX *ctx;
	int server;
	SSL *ssl;
	char buf[1024];
	int bytes;
	char *hostname, *portnum;

	if ( argc != 3 )
	{
		printf("usage: %s <hostname> <portnum>\n", argv[0]);
		exit(0);
	}
	hostname=argv[1];
	portnum=argv[2];

	ctx = InitCTX();
	server = OpenConnection(hostname, atoi(portnum));
	ssl = SSL_new(ctx);				// create new SSL connection state
	SSL_set_fd(ssl, server);			// attach the socket descriptor
	if ( SSL_connect(ssl) == FAIL )			// perform the connection
		ERR_print_errors_fp(stderr);
	else
	{
		char *msg = "Hello World!!";
		
		printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
		ShowCerts(ssl);				// get any certs
		SSL_write(ssl, msg, strlen(msg));	// encrypt & send message
		bytes = SSL_read(ssl, buf, sizeof(buf));// get reply & decrypt
		buf[bytes] = 0;
		printf("Received: \"%s\"\n", buf);
		SSL_free(ssl);				// release connection state
	}
	close(server);					// close socket
	SSL_CTX_free(ctx);				// release context
	return 0;
}
