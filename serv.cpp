// My MINIsocks v 0.01 coded by Gar|k 2010

#pragma comment(linker,"/ENTRY:New_Main")
#pragma comment(linker, "/MERGE:.data=.text")
#pragma comment(linker, "/MERGE:.rdata=.text")
#pragma comment(linker, "/SECTION:.text,EWR")
#ifndef _DEBUG
#pragma comment(linker,"/SUBSYSTEM:windows") 
#endif

#include <winsock2.h> // Wincosk2.h должен быть раньше windows!
#pragma comment(lib, "ws2_32.lib")
#include <windows.h>
#ifdef _DEBUG
#include <stdio.h>
#endif

#include "serv.h"

extern "C" void __cdecl _chkstk() { 
	__asm { 
		push ebp 
			sub eax, 4 
			xchg [esp+4], ebp 
			sub esp, eax 
			xchg [esp], ebp 
			mov ebp, esp 
			add ebp, eax 
			mov ebp, [ebp] 
	} 
}

// создание tcp сервера
SOCKET tcp_server(USHORT port,int max_client)
{
	SOCKET sock=INVALID_SOCKET;
	struct sockaddr_in addr;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock!=INVALID_SOCKET)
	{
#ifdef _DEBUG
		printf("[+] Open socket\n");
#endif
		addr.sin_family = AF_INET;
		addr.sin_port = HTONS(port); // не забываем о сетевом порядке!!!
		addr.sin_addr.s_addr = 0; // сервер принимает подключения на все свои IP адреса

		if (!(bind(sock, (struct sockaddr *)&addr, sizeof(addr))))
		{
#ifdef _DEBUG
			printf("[+] Bind %d port\n",port);
#endif
			if (listen(sock, max_client))
			{
				closesocket(sock);
				sock=INVALID_SOCKET;
			}

#ifdef _DEBUG
			if(sock!=INVALID_SOCKET){
				printf("[+] Listen...\n",port);}
#endif
		}
		else{
			closesocket(sock);
			sock=INVALID_SOCKET;
		}
	}
	return sock;
}

#define SEND 0
#define RECV 1
int tcp_rs(char type,SOCKET s, char *buf, int len, int flags) {
	int total = 0;
	int n;
	if(type==SEND) { 
		tcp_func=(int (__stdcall *)(SOCKET,char *,int,int))&send; } else
		{
			tcp_func=(int (__stdcall *)(SOCKET,char *,int,int))&recv;
		}
		while(total < len) {
			n = tcp_func(s, buf+total, len-total, flags);

			if(n>0) { total += n; }
			else if(n == 0) { 
				//Reconnect(opt);
				closesocket(s);
				return 0;
			}
			else {

				n=WSAGetLastError();
				closesocket(s);
				return (!n+1);

				// 10054 Connection reset by peer 
			}
		}

		return total;
}

ULONG Host2Ip(char * host)
{
	struct hostent * p;
	ULONG ret;
	if (inet_addr(host) != INADDR_NONE) { ret = inet_addr(host); return ret; }

	p = gethostbyname(host);
	if (p) { ret = *(ULONG*)(p->h_addr); }
	else { ret = INADDR_NONE; }
	return ret;
}



int socks5_server(SOCKET client){
	struct _S5_METHOD_REQ s5m_req;
	struct _S5_METHOD_RESP s5m_resp={0x05,0xFF};
	struct _S5_REQ s5_req;
	int k=0,len=0;
	char buf[4096];
	struct fd_set fds_read;
	struct timeval tv={0,0};

	ULONG ip;
	USHORT port;
	struct sockaddr_in dst_addr;
	SOCKET dst_socket;

	// подключение клиента
	RtlZeroMemory(&s5m_req,sizeof(S5_METHOD_REQ));
	if(tcp_rs(RECV,client,(char *)&s5m_req,2,0)!=2) return -1;
	if(tcp_rs(RECV,client,(char *)&s5m_req.methods,s5m_req.nmethods,0)!=s5m_req.nmethods) return -1;
	//s5m_resp.method=0xFF;
	for(k=0;k<s5m_req.nmethods;k++) { 
		if(s5m_req.methods[k]==0x00 || s5m_req.methods[k]==0x02) 
		{ s5m_resp.method=s5m_req.methods[k]; break; }
	} // все метод выбран

	if(tcp_rs(SEND,client,(char *)&s5m_resp,2,0)!=2) return -1; // шлем ответ

	// теперь получаем комманду
	RtlZeroMemory(&s5_req,sizeof(S5_REQ));
	if(tcp_rs(RECV,client,(char *)&s5_req,4,0)!=4) return -1;
	if(s5_req.atype==3)
	{
		if(tcp_rs(RECV,client,(char *)&s5_req.ADDR_TYPE.ADDR_HOST.nlen,1,0)!=1) return -1;
		if(tcp_rs(RECV,client,s5_req.ADDR_TYPE.ADDR_HOST.host,s5_req.ADDR_TYPE.ADDR_HOST.nlen,0)!=s5_req.ADDR_TYPE.ADDR_HOST.nlen) return -1;
		if(tcp_rs(RECV,client,(char *)&port,2,0)!=2) return -1;
		k=5+s5_req.ADDR_TYPE.ADDR_HOST.nlen+2;
		ip=Host2Ip(s5_req.ADDR_TYPE.ADDR_HOST.host);
		if(ip==INADDR_NONE) 
		{
			// ошибка SOCKS5_REPLY_HOST_UNACCESSIBLE
			//printf("[-]ERR 4\n");
			s5_req.command=SOCKS5_REPLY_HOST_UNACCESSIBLE;
			tcp_rs(SEND,client,(char *)&s5_req,k,0);
			closesocket(client);
			return SOCKS5_REPLY_HOST_UNACCESSIBLE;

		}
	}
	// получили теперь смотрм команду
	if(s5_req.command==1) // connect
	{
		dst_socket=socket(AF_INET, SOCK_STREAM, 0);
		dst_addr.sin_family=AF_INET;
		dst_addr.sin_addr.S_un.S_addr=ip;
		dst_addr.sin_port=port;
		if (connect(dst_socket, (struct sockaddr *)&dst_addr, sizeof(dst_addr)))
		{
			closesocket(dst_socket);
			s5_req.command=SOCKS5_REPLY_ERROR_CONNECT; 
			tcp_rs(SEND,client,(char *)&s5_req,k,0);
			closesocket(client);
			return SOCKS5_REPLY_ERROR_CONNECT;
		}
		// подключились
		s5_req.command=SOCKS5_REPLY_OK; 
		if(tcp_rs(SEND,client,(char *)&s5_req,k,0)!=k) return -1;
		//sendall(client,(char *)&port,2,0);

		// теперь надо обмен между клиентом и сервером организовать
		while(1)
		{
			fds_read.fd_count=2;
			fds_read.fd_array[0] = client;
			fds_read.fd_array[1] = dst_socket;

			// запросим инфу о состоянии
			k = select(0, &fds_read, 0, 0, &tv);
			if (k > 0) // если чтото изменилось
			{
				if (__WSAFDIsSet(client, &fds_read)) // если первый сокет очухался
				{
					len=recv(client,buf,4096,MSG_PEEK);
					if(!len) break;
					else { 
						if(tcp_rs(RECV,client,buf,len,0)>0) { 

							if(tcp_rs(SEND,dst_socket,buf,len,0)<=0) break;

						} else break; }
				}
				if (__WSAFDIsSet(dst_socket, &fds_read)) // если первый сокет очухался
				{
					len=recv(dst_socket,buf,4096,MSG_PEEK);
					if(!len) break;
					else { if(tcp_rs(RECV,dst_socket,buf,len,0)>0) { 

						if(tcp_rs(SEND,client,buf,len,0)<=0) break;

					} else break; }
				}
			} 
		Sleep(50); // не отнимаем у проца ресурсы
		}
	}

	return 0;
}

int wtoi(wchar_t *str)
{
	int i, n;
	char s[10];
	CharToOemW(str,s);

	for(i=0, n=0; s[i]>='0' && s[i]<='9'; i++) n = n*10 + (s[i] - '0');
	return n;
}

void New_Main()
{
	SOCKET server_socket;
	SOCKET client_socket; // сокет для клиента
	struct sockaddr_in client_addr; // адрес клиента (заполняется системой)
	int client_addr_size = sizeof(client_addr);
	static struct tcp_keepalive alive={1,5*60*1000,10000}; // автопинг через 5 минут с интервалом в 10 сек

	WSADATA ws;
	LPWSTR *argv; int argc;

	argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	if(argc!=2) goto ex;
	WSAStartup(0x202, &ws);
	RtlZeroMemory = (void (__stdcall *)(void *dst, int count))GetProcAddress(GetModuleHandle("KERNEL32.DLL"), "RtlZeroMemory");

	if((server_socket=tcp_server(wtoi(argv[1]),1))!=INVALID_SOCKET) {
		while ((client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_size)))
		{
			if((WSAIoctl(client_socket, SIO_KEEPALIVE_VALS, &alive, sizeof(alive),NULL, 0, (LPDWORD)&ws, NULL, NULL))!= SOCKET_ERROR) {
				socks5_server(client_socket); }
			client_socket=INVALID_SOCKET;
		}
	}
	WSACleanup();
ex:
	ExitProcess(0);
}