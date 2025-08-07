#include "XYSocket.h"
#include "XYPageBuffer.h"
#include "ssl_shell.h"

#include <Windows.h>

#pragma comment(lib, "crypt32.lib")
#ifdef _M_X64
#pragma comment(lib, "openssl/libraries64/libcrypto.lib")
#pragma comment(lib, "openssl/libraries64/libssl.lib")
#else
#pragma comment(lib, "openssl/libraries32/libcrypto.lib")
#pragma comment(lib, "openssl/libraries32/libssl.lib")
#endif

unsigned char* file_readbuffer(const WCHAR* filename, unsigned int *filesize)
{
	unsigned char* filebuffer = NULL;
	HANDLE hfile;
	DWORD numberofbytes;
	BOOL result = FALSE;

	hfile = CreateFile(filename, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hfile != INVALID_HANDLE_VALUE)
	{
		*filesize = GetFileSize(hfile, NULL);
		filebuffer = new unsigned char[*filesize];
		if (filebuffer)
		{
			ReadFile(hfile, filebuffer, *filesize, &numberofbytes, NULL);
		}

		CloseHandle(hfile);
	}
	return(filebuffer);
}
BOOL file_writebuffer(const WCHAR* filename, const unsigned char* filebuffer, unsigned int filesize)
{
	HANDLE hfile;
	DWORD numberofbytes;
	BOOL result = FALSE;

	hfile = CreateFile(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hfile != INVALID_HANDLE_VALUE)
	{
		WriteFile(hfile, filebuffer, filesize, &numberofbytes, NULL);

		CloseHandle(hfile);
	}
	return(result);
}

inline uint32_t read_4le(const unsigned char* buffer)
{
	uint32_t result;

	result = buffer[0];
	result |= (buffer[1] << 0x08);
	result |= (buffer[2] << 0x10);
	result |= (buffer[3] << 0x18);
	return(result);
}
inline void write_4le(unsigned char* buffer, uint32_t value)
{
	buffer[0] = value;
	buffer[1] = value >> 0x08;
	buffer[2] = value >> 0x10;
	buffer[3] = value >> 0x18;
}
void tester_parse(XYPAGE_BUFFER* pb)
{
	const unsigned char* p;
	unsigned int l;
	unsigned int o;

	o = pb->offset;
	if (o > 4)
	{
		p = pb->buffer1;

		l = read_4le(p);
		printf("l %d, o %d\r\n", l, o);
		if (o >= 4 + l)
		{
			static int sss = 1;
			if (0)
			{
				WCHAR filename[256];
				unsigned int k;

				k = GetModuleFileName(NULL, filename, sizeof(filename) / sizeof(filename[0]));
				if (k && k < sizeof(filename) / sizeof(filename[0]))
				{
					while (k)
					{
						k--;

						if (filename[k] == '\\' || filename[k] == '/')
						{
							k++;

							break;
						}
					}
				}
				wsprintf(filename + k, L"%02d.bmp", sss & 0x1f);
				sss++;
				file_writebuffer(filename, p + 4, l);
			}

			ReadPageBuffer(pb, NULL, 4 + l);
		}
	}
}

struct my_conn
{
	struct _ssl_conn pss[1];

	// 接收数据
	XYPAGE_BUFFER pb[1];

	unsigned int flags;
};

int CALLBACK SocketProcedure(LPVOID parameter, LPVOID **pointer, LPVOID context, 
	SOCKET s, BYTE type, BYTE number, SOCKADDR *psa, int *salength, const char *buffer, int length)
{
	PXYSOCKET ps = (PXYSOCKET)parameter;
	struct _ssl_shell *pshell = (struct _ssl_shell *)ps->parameter1;
	PXYSOCKET_CONTEXT psc = (PXYSOCKET_CONTEXT)context;
	struct my_conn *pconn;
	XYPAGE_BUFFER* pb;
	unsigned char *p;
	int result = 0;
	unsigned int l0;
	unsigned int l1;
	unsigned int l;
	unsigned int bufferlength;
	unsigned char address[0x1c04];
	PSOCKADDR_IN psai;
	int err;
	unsigned char command;

	switch (number)
	{
	case XYSOCKET_CLOSE:
		switch (type)
		{
		case XYSOCKET_TYPE_TCP:
			break;
		case XYSOCKET_TYPE_TCP0:
		case XYSOCKET_TYPE_TCP1:
			pconn = (struct my_conn *)psc->context;
			_ssl_session_uninitialize((struct _ssl_conn *)pconn);
			UninitializePageBuffer(pconn->pb);
			FREE(pconn);
			//
			break;
		default:
			break;
		}
		break;
	case XYSOCKET_CONNECT:
		switch (type)
		{
		case XYSOCKET_TYPE_TCP0:
			switch (length)
			{
			case 0:
				// 成功
				if (pointer)
				{
					pconn = (struct my_conn *)psc->context;
					if (pconn)
					{
						pconn->flags = 0;

						if (_sslconn_initialize((struct _ssl_conn *)pconn, pshell->ctx1, 1))
						{
							_ssl_handshake((struct _ssl_conn *)pconn, &err, s);
						}
					}
				}
				break;
			case XYSOCKET_ERROR_FAILED:
			case XYSOCKET_ERROR_REFUSED:
			case XYSOCKET_ERROR_OVERFLOW:
			default:
				break;
			}
			break;
		case XYSOCKET_TYPE_TCP1:
			switch (length)
			{
			case XYSOCKET_ERROR_ACCEPT:
				psai = (PSOCKADDR_IN)psa;

				psai->sin_family = AF_INET;

				*salength = sizeof(SOCKADDR_IN);
				break;
			case XYSOCKET_ERROR_ACCEPTED:
				OutputDebugString(L"Server accept ok\r\n");
				{
					if (pconn = (struct my_conn *)MALLOC(sizeof(struct my_conn)))
					{
						pconn->flags = 0;

						InitializePageBuffer(pconn->pb, NULL, 0, 0x100);

						if (_sslconn_initialize((struct _ssl_conn *)pconn, pshell->ctx0, 0))
						{
						}

						psc->context = pconn;
					}
				}
				break;
			case XYSOCKET_ERROR_OVERFLOW:
				break;
			default:
				break;
			}
			break;
		default:
			break;
		}
		break;
	case XYSOCKET_RECV:
		switch (type)
		{
		case XYSOCKET_TYPE_TCP0:
			// 这里是 client 的 socket
		case XYSOCKET_TYPE_TCP1:
			// 这里是 server 的 socket
			if (pointer == NULL)
			{
				pconn = (struct my_conn *)psc->context;

				int connected = 0;
				int flag = 1;

				pb = pconn->pb;
				int rv = _ssl_read((struct _ssl_conn*)pconn, s,
					(const unsigned char *)buffer, length,
					&connected, pb);
				//printf("_ssl_read connected %d, rv %d, %d, %d\r\n", connected, rv, pconn->flags, pb->offset);
				if (connected && (pconn->flags & 1) == 0)
				{
					if (type == XYSOCKET_TYPE_TCP0)
					{
						//if ((pconn->flags & 1) == 0)
						{
							const char* request = "GET / HTTP/1.1\r\n"
								"Connection: keep-alive\r\n"
								"User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0)\r\n"
								"Host: %s:%d\r\n"
								"Pragma: no-cache\r\n"
								"Content-Type: application/octet-stream\r\n"
								"Accept-Encoding: deflate, gzip\r\n\r\n";

							char reqbuf[1024];
							wsprintfA(reqbuf, request, "www.baidu.com", 443);

							_ssl_write((struct _ssl_conn *)pconn, s,
								(const unsigned char *)reqbuf, strlen(reqbuf));
						}
					}
					else
					{
						const char* response = "HTTP/1.1 200 OK\r\n"
							"Connection: keep-alive\r\n"
							"Pragma: no-cache\r\n"
							"Content-Type: application/octet-stream\r\n"
							"Accept-Encoding: deflate, gzip\r\n\r\n";

						_ssl_write((struct _ssl_conn *)pconn, s,
							(const unsigned char *)response, strlen(response));

						if (0)
						{
							unsigned char* buffer;
							unsigned char* filebuffer;
							unsigned int filesize;

							filebuffer = file_readbuffer(L"AA.bmp", &filesize);
							if (filebuffer)
							{
								buffer = new unsigned char[4 + filesize];
								if (buffer)
								{
									write_4le(buffer, filesize);
									memcpy(buffer + 4, filebuffer, filesize);
								}
								delete[] filebuffer;
								if (buffer)
								{
									while (1)
									{
										_ssl_write((struct _ssl_conn *)pconn, s,
											(const unsigned char *)buffer, 4 + filesize);

										//Sleep(1000);
									}

									delete[] buffer;
								}
							}
						}
					}

					//pconn->flags |= 1;
				}
				if (pb->offset)
				{
					//tester_parse(pb);
					char tbuf[8196];
					if (pb->offset + 1 < sizeof(tbuf))
					{
						memcpy(tbuf, pb->buffer1, pb->offset);
						tbuf[pb->offset] = '\0';
						printf("%s\r\n", tbuf);
					}
					pb->offset = 0;
				}
			}
			break;
		default:
			break;
		}
		break;
	case XYSOCKET_SEND:
		break;
	case XYSOCKET_TIMEOUT:
		switch (type)
		{
		case XYSOCKET_TYPE_TCP:
			//OutputDebugString(_T("listener timeout\r\n"));
			break;
		case XYSOCKET_TYPE_TCP0:
			break;
		case XYSOCKET_TYPE_TCP1:
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	return(result);
}

int wmain(int argc, WCHAR *argv[])
{
	XYSOCKET ps[1];
	struct _ssl_shell pshell[1];
	struct my_conn *pconn;
	SOCKET fd;

	if (argc > 1)
	{
		WSADATA wsad;

		WSAStartup(MAKEWORD(2, 2), &wsad);

		_ssl_initialize(pshell);

		XYSocketsStartup(ps, NULL, (LPVOID)pshell, SocketProcedure);

		unsigned int i;
		unsigned int j;
		char str[256];
		char ch;

		i = 0;
		j = 0;
		while (ch = str[i] = argv[1][i])
		{
			if (ch >= '0' && ch <= '9')
			{
			}
			else
			{
				//break;
			}

			if (ch == ':')
			{
				j = i + 1;
			}

			i++;
		}

		struct sockaddr_in sai;

		sai.sin_family = AF_INET;

		fd = -1;

		if (j)
		{
			XYSocketLaunchThread(ps, XYSOCKET_THREAD_CONNECT, 64);
			XYSocketLaunchThread(ps, XYSOCKET_THREAD_CLIENT, 64);

			str[j - 1] = '\0';
			sai.sin_addr.S_un.S_addr = inet_addr(str);
			sai.sin_port = htons(atoi(str + j));

			if (pconn = (struct my_conn *)MALLOC(sizeof(struct my_conn)))
			{
				InitializePageBuffer(pconn->pb, NULL, 0, 0x100);

				fd = XYTCPConnect(ps, (void *)pconn, (const struct sockaddr*)&sai, sizeof(sai), 0);
			}
		}
		else
		{
			XYSocketLaunchThread(ps, XYSOCKET_THREAD_LISTEN, 64);
			XYSocketLaunchThread(ps, XYSOCKET_THREAD_SERVER, 1024);

			const char *pcrt_file = "server-cert.pem";
			const char *pkey_file = "server-key.pem";
			char crt_file[128];
			char key_file[128];

			if (argc > 3)
			{
				i = 0;
				while (crt_file[i] = argv[2][i])
				{
					i++;
				}
				i = 0;
				while (key_file[i] = argv[3][i])
				{
					i++;
				}

				pcrt_file = crt_file;
				pkey_file = key_file;
			}

			_ssl_inhale(pshell->ctx0,
				pcrt_file, pkey_file, "ALL:!EXPORT:!LOW");

			sai.sin_port = htons(atoi(str));
			sai.sin_addr.s_addr = htonl(INADDR_ANY);

			fd = XYTCPListen(ps, NULL, NULL, (const SOCKADDR *)&sai, sizeof(sai));
		}

		getchar();

		XYSocketsCleanup(ps);

		_ssl_uninitialize(pshell);

		WSACleanup();
	}

	return(0);
}
