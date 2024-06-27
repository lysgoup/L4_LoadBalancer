#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/sysinfo.h>
#include <time.h>

#define BUF_SIZE 40
#define EPOLL_SIZE 50

enum algorithms{
  RR,
  LEAST_CONN,
  RESOURCE_BASED
};

time_t prev_time, cur_time;

void error_handling(char *buf)
{
	fputs(buf, stderr);
	fputc('\n', stderr);
	exit(1);
}

double get_cpu_usage() {
    long double a[4], b[4], loadavg;
    FILE *fp;

    fp = fopen("/proc/stat", "r");
    if (!fp) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }
    fscanf(fp, "%*s %Lf %Lf %Lf %Lf", &a[0], &a[1], &a[2], &a[3]);
    fclose(fp);
    sleep(1);

    fp = fopen("/proc/stat", "r");
    if (!fp) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }
    fscanf(fp, "%*s %Lf %Lf %Lf %Lf", &b[0], &b[1], &b[2], &b[3]);
    fclose(fp);

    loadavg = ((b[0] + b[1] + b[2]) - (a[0] + a[1] + a[2])) /
              ((b[0] + b[1] + b[2] + b[3]) - (a[0] + a[1] + a[2] + a[3]));
    return loadavg * 100;
}

long get_ram_usage() {
    struct sysinfo info;
    if (sysinfo(&info) != 0) {
        perror("sysinfo");
        exit(EXIT_FAILURE);
    }
    return info.totalram - info.freeram;
}

void send_resource_info(int sock){
	double cpu_usage;
	long ram_usage;
	cpu_usage = get_cpu_usage();
	ram_usage = get_ram_usage() / 1000000;

	printf("CPU Usage: %.2f%%, RAM Usage: %ld Mb\n", cpu_usage, ram_usage);

	int resource_usage = (int)cpu_usage + (int)ram_usage;
	printf("Send to server: %d\n",resource_usage);

	send(sock,&resource_usage,sizeof(int),0);
	prev_time = cur_time;
}

int main(int argc, char *argv[])
{
	// Connect to LB
	int lb_sock;
	struct sockaddr_in lb_adr;
	int lb_algorithm;

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

	int optval = 1;
	if (setsockopt(serv_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1) {
		perror("setsockopt(SO_REUSEADDR)");
		close(serv_sock);
		exit(EXIT_FAILURE);
	}
	
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
		time(&cur_time);
		if(lb_algorithm==RESOURCE_BASED && difftime(cur_time, prev_time) >= 10.0) send_resource_info(lb_sock);
		event_cnt=epoll_wait(epfd, ep_events, EPOLL_SIZE, 0);
		if(event_cnt==0) continue;
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