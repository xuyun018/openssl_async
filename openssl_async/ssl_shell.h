//---------------------------------------------------------------------------
// 
//---------------------------------------------------------------------------
#ifndef _SSL_SHELL_H
#define _SSL_SHELL_H
//---------------------------------------------------------------------------
#include "XYSocket.h"
#include "XYPageBuffer.h"
#include "openssl/headers/ssl.h"
#include "openssl/headers/err.h"
//---------------------------------------------------------------------------
struct _ssl_shell
{
	// server
	SSL_CTX *ctx0;
	// client
	SSL_CTX *ctx1;
};

struct _ssl_conn
{
	SSL *s;

	// the ssl BIO used only by openSSL
	BIO* b;
	//Our BIO, All IO should be through this
	// 用户使用
	BIO* b1;
};
//---------------------------------------------------------------------------
void _ssl_initialize(struct _ssl_shell *pshell);
void _ssl_uninitialize(struct _ssl_shell *pshell);

int _ssl_inhale(SSL_CTX *ctx,
	const char *cert_file, const char *key_file, const char *str);

int _sslconn_initialize(struct _ssl_conn *pconn, SSL_CTX *ctx, int c);
void _ssl_session_uninitialize(struct _ssl_conn *pconn);

int _ssl_handshake(struct _ssl_conn *pconn, int *err, int fd);

int _ssl_read(struct _ssl_conn *pconn, int fd,
	const unsigned char *buf, unsigned int len,
	int *connected, XYPAGE_BUFFER *pb);
int _ssl_write(struct _ssl_conn *pconn, int fd,
	const unsigned char *buf, unsigned int len);
//---------------------------------------------------------------------------
#endif