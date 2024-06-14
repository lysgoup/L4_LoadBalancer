#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#define BUF_SIZE 40
#define EPOLL_SIZE 50

enum algorithms{
  RR,
  LEAST_CONN,
  RESOURCE_BASED
};

void error_handling(char *buf)
{
	fputs(buf, stderr);
	fputc('\n', stderr);
	exit(1);
}

int main(int argc, char *argv[])
{
	// Connect to LB
	int lb_sock;
	struct sockaddr_in lb_adr;

	if (argc != 4) {
		printf("Usage : %s <LB_IP> <LB_port> <port>\n", argv[0]);
		exit(1);
	}

	lb_sock = socket(PF_INET, SOCK_STREAM, 0);   
	if (lb_sock == -1)
		error_handling("socket() error");
	
	memset(&lb_adr, 0, sizeof(lb_adr));
	lb_adr.sin_family = AF_INET;
	lb_adr.sin_addr.s_addr = inet_addr(argv[1]);
	lb_adr.sin_port = htons(atoi(argv[2]));
	
	if (connect(lb_sock, (struct sockaddr*)&lb_adr, sizeof(lb_adr)) == -1){
		error_handling("connect() error!");
	}
	else{
		int lb_algorithm;
		int check = recv(lb_sock,&lb_algorithm,sizeof(int),0);
		if(check == 0){
			puts("Connection Failed: You may have exceeded the number of servers that can connect to LB.");
			close(lb_sock);
			exit(0);
		}
		else{
			printf("Connected to Load Balancer: %d\n",lb_algorithm);
			u_short port_for_client = (u_short)(atoi(argv[3]));
			printf("port_for_client: %d\n",port_for_client);
			send(lb_sock,&port_for_client,sizeof(u_short),0);
		}
	}

	// Open listen sock
	int serv_sock, clnt_sock;
	struct sockaddr_in serv_adr, clnt_adr;
	socklen_t adr_sz;
	int str_len, i;
	char buf[BUF_SIZE];

	struct epoll_event *ep_events;
	struct epoll_event event;
	int epfd, event_cnt;

	serv_sock=socket(PF_INET, SOCK_STREAM, 0);
	memset(&serv_adr, 0, sizeof(serv_adr));
	serv_adr.sin_family=AF_INET;
	serv_adr.sin_addr.s_addr=htonl(INADDR_ANY);
	serv_adr.sin_port=htons(atoi(argv[3]));
	
	if(bind(serv_sock, (struct sockaddr*) &serv_adr, sizeof(serv_adr))==-1)
		error_handling("bind() error");
	if(listen(serv_sock, 5)==-1)
		error_handling("listen() error");

	epfd=epoll_create(EPOLL_SIZE);
	ep_events=malloc(sizeof(struct epoll_event)*EPOLL_SIZE);

	event.events=EPOLLIN;
	event.data.fd=serv_sock;	
	epoll_ctl(epfd, EPOLL_CTL_ADD, serv_sock, &event);

	event.events=EPOLLIN;
	event.data.fd=lb_sock;
	epoll_ctl(epfd, EPOLL_CTL_ADD, lb_sock, &event);

	while(1)
	{
		event_cnt=epoll_wait(epfd, ep_events, EPOLL_SIZE, -1);
		if(event_cnt==-1)
		{
			puts("epoll_wait() error");
			break;
		}

		puts("return epoll_wait");
		for(i=0; i<event_cnt; i++)
		{
			if(ep_events[i].data.fd==serv_sock)
			{
				adr_sz=sizeof(clnt_adr);
				clnt_sock=accept(serv_sock, (struct sockaddr*)&clnt_adr, &adr_sz);
				event.events=EPOLLIN;
				event.data.fd=clnt_sock;
				epoll_ctl(epfd, EPOLL_CTL_ADD, clnt_sock, &event);
				printf("connected client: %d \n", clnt_sock);
			}
			else
			{
				str_len=read(ep_events[i].data.fd, buf, BUF_SIZE);
				if(str_len==0)    // close request!
				{
					if(ep_events[i].data.fd == lb_sock){
						close(ep_events[i].data.fd);
						printf("LB connection broken\n");
						exit(1);
					}
					epoll_ctl(epfd, EPOLL_CTL_DEL, ep_events[i].data.fd, NULL);
					close(ep_events[i].data.fd);
					printf("closed client: %d \n", ep_events[i].data.fd);
				}
				else
				{
					write(ep_events[i].data.fd, buf, str_len);    // echo!
				}
			}
		}
	}
	close(serv_sock);
	close(epfd);
	return 0;
}