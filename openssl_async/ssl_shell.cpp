#include "ssl_shell.h"

#include <stdlib.h>
#include <string.h>
//---------------------------------------------------------------------------
int _ssl_err_hdlr(SSL *s, BIO *b, int r, int fd)
{
	int pending;

	if (r <= 0)
	{
		switch (r = SSL_get_error(s, r))
		{
		case SSL_ERROR_NONE: //0
		case SSL_ERROR_SSL:  // 1
			//don't break, flush data first

		case SSL_ERROR_WANT_READ: // 2
		case SSL_ERROR_WANT_WRITE: // 3
		case SSL_ERROR_WANT_X509_LOOKUP:  // 4
			pending = BIO_ctrl(b, BIO_CTRL_PENDING, 0, NULL);
			if (pending > 0)
			{
				char *buf;

				// 这里可以马上发送出去, 也可以先存起来推迟再发送
				// (所谓推迟只是把数据集中)
				buf = new char[pending];
				if (buf)
				{
					BIO_read(b, buf, pending);

					XYTCPSend((SOCKET)fd, buf, pending, 0);

					delete[] buf;
				}
			}
			break;
		case SSL_ERROR_ZERO_RETURN: // 5
		case SSL_ERROR_SYSCALL: //6
		case SSL_ERROR_WANT_CONNECT: //7
		case SSL_ERROR_WANT_ACCEPT: //8
		default:
			break;
		}
	}
	return(r);
}
int _ssl_handshake(struct _ssl_conn *pconn, int *err, int fd)
{
	SSL *s = pconn->s;
	BIO *b = pconn->b1;
	int r;

	r = SSL_do_handshake(s);
	if (r <= 0)
	{
		switch (*err = _ssl_err_hdlr(s, b, r, fd))
		{
		case SSL_ERROR_NONE: //0
		case SSL_ERROR_SSL:  // 1
		case SSL_ERROR_ZERO_RETURN: // 5
		case SSL_ERROR_SYSCALL: //6
		case SSL_ERROR_WANT_CONNECT: //7
		case SSL_ERROR_WANT_ACCEPT: //8
			break;
		default:
			*err = 0;
			break;
		}
	}
	return(r);
}

int _sslconn_initialize(struct _ssl_conn *pconn, SSL_CTX *ctx, int c)
{
	SSL *s;
	BIO *b;
	BIO *b1;

	pconn->s = NULL;
	pconn->b = NULL;
	pconn->b1 = NULL;

	if (s = SSL_new(ctx))
	{
		if (c)
		{
			SSL_set_connect_state(s);
		}
		else
		{
			SSL_set_accept_state(s);
		}

		BIO_new_bio_pair(&b, 0, &b1, 0);

		BIO_up_ref(b);
		BIO_up_ref(b1);

		SSL_set_bio(s, b, b);

		pconn->s = s;
		pconn->b = b;
		pconn->b1 = b1;
	}
	return(c);
}
void _ssl_session_uninitialize(struct _ssl_conn *pconn)
{
	if (pconn->s)
	{
		SSL_free(pconn->s);
		pconn->s = NULL;
	}

	if (pconn->b)
	{
		BIO_free(pconn->b);
		pconn->b = NULL;
	}
	if (pconn->b1)
	{
		BIO_free(pconn->b1);
		pconn->b1 = NULL;
	}
}

int _ssl_read(struct _ssl_conn *pconn, int fd,
	const unsigned char *buf, unsigned int len,
	int *connected, XYPAGE_BUFFER *pb)
{
	SSL *s = pconn->s;
	BIO *b = pconn->b1;
	unsigned char *_buf;
	int err = 0;
	int r;

	while (len)
	{
		r = BIO_write(b, buf, len);
		if (r > 0)
		{
			buf += r;
			len -= r;
		}
		else
		{
			len = -len;

			break;
		}
		if (*connected == 0)
		{
			*connected = SSL_is_init_finished(s) || _ssl_handshake(pconn, &err, fd) == 1;
		}

		if (*connected)
		{
			do
			{
				r = 0;
				if (WritePageBuffer(pb, NULL, r = SSL3_RT_MAX_PLAIN_LENGTH))
				{
					_buf = pb->buffer1 + pb->offset;
					r = SSL_read(s, (void*)_buf, r);
					if (r > 0)
					{
						pb->offset += r;
					}
					else
					{
						_ssl_err_hdlr(s, b, r, fd);

						break;
					}
				}
			} while (r > 0);
		}
		else
		{
			if (err)
			{
				len = -len;

				break;
			}
		}
	}

	return(0);
}
int _ssl_write(struct _ssl_conn *pconn, int fd,
	const unsigned char *buf, unsigned int len)
{
	SSL *s = pconn->s;
	BIO *b = pconn->b1;
	char *_buf;
	int pending;
	int r;

	do
	{
		//this should give me something to write to client
		r = SSL_write(s, buf, len);
		if (r > 0)
		{
			buf += r;
			len -= r;

			if ((pending = BIO_ctrl(b, BIO_CTRL_PENDING, 0, NULL)) > 0)
			{
				// 这里可以马上发送出去, 也可以先存起来推迟再发送
				// (所谓推迟只是把数据集中)
				_buf = new char[pending];
				if (_buf)
				{
					BIO_read(b, _buf, pending);

					XYTCPSend((SOCKET)fd, _buf, pending, 0);

					delete[] _buf;
				}
			}
		}
	} while (r > 0 && len);

	return(len);
}

void ssl_info_callback(const SSL *ssl, int where, int ret) {
	const char *state_str = SSL_state_string_long(ssl);
	const char *where_str = NULL;

	if (where & SSL_CB_LOOP) {
		where_str = "LOOP";
	}
	else if (where & SSL_CB_HANDSHAKE_START) {
		where_str = "HANDSHAKE_START";
	}
	else if (where & SSL_CB_HANDSHAKE_DONE) {
		where_str = "HANDSHAKE_DONE";
		printf("✅ TLS handshake done: version=%s, cipher=%s\n",
			SSL_get_version(ssl), SSL_get_cipher(ssl));
	}
	else if (where & SSL_CB_READ) {
		where_str = "READ";
	}
	else if (where & SSL_CB_WRITE) {
		where_str = "WRITE";
	}
	else if (where & SSL_CB_ALERT) {
		where_str = (where & SSL_CB_READ) ? "ALERT_READ" : "ALERT_WRITE";
		printf("⚠️  TLS alert: %s: %s\n",
			SSL_alert_type_string_long(ret),
			SSL_alert_desc_string_long(ret));
	}
	else {
		where_str = "UNKNOWN";
	}

	printf("[SSL %s] %s\n", where_str, state_str);
}

void _ssl_initialize(struct _ssl_shell *pshell)
{
	SSL_CTX *ctx;

	// 初始化 openssl 库
	OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL);

	ERR_clear_error();
	//

	//pshell->ctx0 = ctx = SSL_CTX_new(TLS_method());
	pshell->ctx0 = ctx = SSL_CTX_new(TLS_server_method());
	if (ctx)
	{
		//SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
		//SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);

		SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
		SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

		SSL_CTX_ctrl(ctx, SSL_CTRL_MODE, 
			SSL_MODE_AUTO_RETRY |
			SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
			SSL_MODE_ENABLE_PARTIAL_WRITE, 
			NULL);

		SSL_CTX_ctrl(ctx, SSL_CTRL_MODE,
			SSL_MODE_RELEASE_BUFFERS,
			NULL);

		// 设置 cipher（TLS 1.2）
		SSL_CTX_set_cipher_list(ctx,
			"ECDHE-RSA-AES128-GCM-SHA256:"
			"ECDHE-RSA-AES256-GCM-SHA384");

		// 设置 TLS 1.3 cipher（OpenSSL >= 1.1.1）
		SSL_CTX_set_ciphersuites(ctx,
			"TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384");

		SSL_CTX_set_info_callback(ctx, ssl_info_callback);

		//// 设置 cipher suite（确保同时支持 RSA 和 RSA-PSS）
		//SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:TLS_AES_128_GCM_SHA256");
		//// 设置 signature algorithms（支持 RSA 和 RSA-PSS）
		//SSL_CTX_set1_sigalgs_list(ctx, "rsa_pss_rsae_sha256:rsa_pkcs1_sha256");
	}

	pshell->ctx1 = ctx = SSL_CTX_new(TLS_client_method());
	if (ctx)
	{
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

		//// 设置 cipher suite（确保同时支持 RSA 和 RSA-PSS）
		//SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:TLS_AES_128_GCM_SHA256");
		//// 设置 signature algorithms（支持 RSA 和 RSA-PSS）
		//SSL_CTX_set1_sigalgs_list(ctx, "rsa_pss_rsae_sha256:rsa_pkcs1_sha256");
	}
}
void _ssl_uninitialize(struct _ssl_shell *pshell)
{
	SSL_CTX **ctx;

	ctx = &pshell->ctx0;
	if (*ctx)
	{
		SSL_CTX_up_ref(*ctx);
		*ctx = NULL;
	}

	ctx = &pshell->ctx1;
	if (*ctx)
	{
		SSL_CTX_up_ref(*ctx);
		*ctx = NULL;
	}
}

//Need to enhance
int __tls_verify_peer(int ok, X509_STORE_CTX* ctx)
{
	return 1;
}
int _ssl_inhale(SSL_CTX *ctx, 
	const char *cert_file, const char *key_file, const char *str)
{
	int r;

	//TODO: Change this later, no hardcoding 
#define CIPHERS    "ALL:!EXPORT:!LOW"
	//r = pois->p_SSL_CTX_set_cipher_list(ctx, str);
	r = 1;
	if (r == 1)
	{
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, __tls_verify_peer);

		printf("SSL_CTX_set_verify\r\n");
		r = SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM);
		if (r == 1)
		{
			printf("SSL_CTX_use_certificate_file\r\n");
			r = SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM);
			if (r == 1)
			{
				printf("SSL_CTX_use_PrivateKey_file\r\n");
				r = SSL_CTX_check_private_key(ctx);
			}
		}
	}

	return(r);
}
//---------------------------------------------------------------------------