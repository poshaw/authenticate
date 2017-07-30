/*
** server.c -- a stream socket server demo
** $ make --file=mfs && ./server
** 
** Make cert using:
** $ openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout mycert.pem -out mycert.pem
** 
**  Country Name (2 letter code) [XX]:US
**  State or Province Name (full name) []:OK
**  Locality Name (eg, city) [Default City]:Oklahoma City
**  Organization Name (eg, company) [Default Company Ltd]:Boeing
**  Organizational Unit Name (eg, section) []:RADAR
**  Common Name (eg, your name or your server's hostname) []:phil
**  Email Address []:phillip.o.shaw@boeing.com
** 
*/

#include <arpa/inet.h>
#include <errno.h>
#include <malloc.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <resolv.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define FAIL -1

int OpenListener(int port)
{
	int sd;
	struct sockaddr_in addr;

	sd = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if ( bind(sd, (const struct sockaddr *)&addr, sizeof(addr)) != 0 )
	{
		perror("can't bind port");
		abort();
	}
	if ( listen(sd, 10) != 0 )
	{
		perror("Cant configure listening port");
		abort();
	}
	return sd;
}

SSL_CTX* InitServerCTX(void)
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	SSL_library_init();
	OpenSSL_add_all_algorithms();				// Load & register all cryptos etc.
	SSL_load_error_strings();				// Load all error messages
	method = SSLv2_server_method();				// create new server-method instance
	ctx = SSL_CTX_new(method);				// creat new context from method
	if ( ctx == NULL )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
	// set the local certificate from CertFile
	if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	// set the private key from KeyFile (may be same as CertFile)
	if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	// verify private key
	if ( !SSL_CTX_check_private_key(ctx))
	{
		fprintf(stderr, "Private key does not match the public certificate\n");
		abort();
	}
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

void Servlet(SSL* ssl)
{
	char buf[1024];
	char reply[1024];
	int sd, bytes;

	if (SSL_accept(ssl) == FAIL )
		ERR_print_errors_fp(stderr);
	else
	{
		ShowCerts(ssl);
		bytes = SSL_read(ssl, buf, sizeof(buf));	// get request
		if ( bytes > 0 )
		{
			buf[bytes] = 0;
			printf("Client msg: \"%s\"\n", buf);
			sprintf(reply, "howdy!!");
			SSL_write(ssl, reply, strlen(reply));	// send reply
		}
		else
			ERR_print_errors_fp(stderr);
	}
	sd = SSL_get_fd(ssl);					// get socket connection
	SSL_free(ssl);						// release SSL state
	close(sd);						// close connection
}

int main(int argc, char *argv[])
{
	SSL_CTX *ctx;
	int server;
	char *portnum;

	if ( argc != 2 )
	{
		printf("Usage: %s <portnum>\n", argv[0]);
		exit(0);
	}
	portnum = argv[1];
	ctx = InitServerCTX();					// initialize SSL
	LoadCertificates(ctx, "mycert.pem", "mycert.pem");	// load certs
	server = OpenListener(atoi(portnum));			// create server socket
	while (1)
	{
		struct sockaddr_in addr;
		int len = sizeof(addr);
		SSL *ssl;

		int client = accept(server, (struct sockaddr *)&addr, (socklen_t *)&len);
		printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, client);			// set connection socket to SSL state
		Servlet(ssl);					// service connection
	}
	close(server);
	SSL_CTX_free(ctx);
	return 0;
}
