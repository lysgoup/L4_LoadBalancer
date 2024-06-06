#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#define BUF_SIZE 40
#define EPOLL_SIZE 50
#define MAX_SERV_CNT 1

enum algorithms{
  RR,
  LEAST_CONN,
  RESOURCE_BASED
};

typedef struct _serv_stat_node{
  int sock;
  char *ip;
  int port;
  int clnt_cnt;
	struct sockaddr sock_adr;
	float resource_usage; // cpu_usage + ram_usage %
}serv_stat_node;

int serv_cnt;
serv_stat_node serv_list[MAX_SERV_CNT];

void error_handling(char *buf)
{
	fputs(buf, stderr);
	fputc('\n', stderr);
	exit(1);
}

void setnonblockingmode(int fd)
{
	int flag=fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flag|O_NONBLOCK);
}

char *make_algo_string(int algo)
{
  char *algo_string = (char *)malloc(32);
  switch(algo){
    case RR:
      strcpy(algo_string,"Round Robin");
      break;
    case LEAST_CONN:
      strcpy(algo_string,"Least Connection");
      break;
    case RESOURCE_BASED:
      strcpy(algo_string,"Resource Based");
      break;
    default:
      printf("Invalid algorithm number!\n[algorithm num]\n- RR:0\n- Least Connection:1\n- Resource Based: 2\n");
      exit(0);
  }
  return algo_string;
}

int add_server_info(int sock, char *ip, int port)
{
  for(int i=0;i<MAX_SERV_CNT;i++){
    if(serv_list[i].sock == 0){
      serv_list[i].sock = sock;
      serv_list[i].ip = (char *)malloc(strlen(ip));
      strcpy(serv_list[i].ip,ip);
      serv_list[i].port = port;
      serv_list[i].clnt_cnt = 0;
    }
    break;
  }
  serv_cnt++;
  return 0;
}

int delete_server_list(int sock){
  for(int i=0;i<MAX_SERV_CNT;i++){
    if(serv_list[i].sock == sock){
      free(serv_list[i].ip);
      memset(&serv_list[i],0,sizeof(serv_stat_node));
    }
    break;
  }
  serv_cnt--;
}

int main(int argc, char *argv[]){
  int lb_sock, serv_sock, clnt_sock;
	struct sockaddr_in lb_adr, serv_adr, clnt_adr;
	socklen_t adr_sz;
	int str_len;
	char buf[BUF_SIZE];

	struct epoll_event *ep_events;
	struct epoll_event event;
	int epfd, event_cnt;
  
  // Argument Parsing
  if(argc != 4){
    printf("Usage : %s <port for server> <port for clients> <algorithm num>\n[algorithm num]\n- RR:0\n- Least Connection:1\n- Resource Based: 2\n",argv[0]);
    exit(1);
  }

  enum algorithms selected_algo = atoi(argv[3]);
  char *selected_algo_string = make_algo_string(selected_algo);
  printf("Selected Algorithm: %s\n",selected_algo_string);
  free(selected_algo_string);

  // Open Socket for Server(TCP)
  lb_sock=socket(PF_INET, SOCK_STREAM, 0);
	memset(&lb_adr, 0, sizeof(lb_adr));
	lb_adr.sin_family=AF_INET;
	lb_adr.sin_addr.s_addr=htonl(INADDR_ANY);
	lb_adr.sin_port=htons(atoi(argv[1]));

  if(bind(lb_sock, (struct sockaddr*) &lb_adr, sizeof(lb_adr))==-1)
		error_handling("bind() error");
	if(listen(lb_sock, 5)==-1)
		error_handling("listen() error");
  
  // Server EPOLL
  epfd=epoll_create(EPOLL_SIZE);
	ep_events=malloc(sizeof(struct epoll_event)*EPOLL_SIZE);
  setnonblockingmode(lb_sock);
	event.events=EPOLLIN;
	event.data.fd=lb_sock;	
	epoll_ctl(epfd, EPOLL_CTL_ADD, lb_sock, &event);

  // TODO Open Socket for Client(RAW)
  // TODO Open Socket for Server(RAW)
  // Init Server List : 연결된 서버 목록
  serv_cnt = 0;
  for(int i=0;i<MAX_SERV_CNT;i++){
    memset(serv_list,0,sizeof(serv_stat_node));
  }
  // TODO init_Client_List : 연결된 클라이언트 목록
	// TODO init_forwarding_table : 서버-클라이언트 연결 리스트
	// TODO init_connection_list : 3-way handshake 완료 여부
	// TODO init_health_check_timer
  
  while(1){
    // Server Epoll Wait
    event_cnt=epoll_wait(epfd, ep_events, EPOLL_SIZE, -1);
    if(event_cnt==-1){
      puts("epoll_wait() error");
			break;
    }
    puts("epoll_wait.....");
    for(int i=0;i<event_cnt;i++){
      // When new server connected
      if(ep_events[i].data.fd==lb_sock){
        adr_sz=sizeof(serv_adr);
				serv_sock=accept(lb_sock, (struct sockaddr*)&serv_adr, &adr_sz);
        if(serv_cnt == MAX_SERV_CNT){
          printf("New Server Connection denied: SERVER IS MAX\n");
          close(serv_sock);
        }
        else{
          setnonblockingmode(serv_sock);
          event.events=EPOLLIN|EPOLLET;
          event.data.fd=serv_sock;
          epoll_ctl(epfd, EPOLL_CTL_ADD, serv_sock, &event);

          char server_ip[INET_ADDRSTRLEN];
          inet_ntop(AF_INET, &serv_adr.sin_addr, server_ip, INET_ADDRSTRLEN);

          // Update Server List
          add_server_info(serv_sock,server_ip,ntohs(serv_adr.sin_port));
          printf("Connected Server: %d [%s:%d]\nServer count: %d\n", serv_sock,server_ip,ntohs(serv_adr.sin_port),serv_cnt);

          // Connection complete
          send(serv_sock,&selected_algo,sizeof(int),MSG_NOSIGNAL);
        }
      }
      else{
        while(1){
					str_len=read(ep_events[i].data.fd, buf, BUF_SIZE);
					if(str_len==0){
						epoll_ctl(epfd, EPOLL_CTL_DEL, ep_events[i].data.fd, NULL);
						close(ep_events[i].data.fd);

            // Update Server List
            delete_server_list(ep_events[i].data.fd);
						printf("closed client: %d \nServer count: %d\n", ep_events[i].data.fd,serv_cnt);
						break;
					}
					else if(str_len<0){
						if(errno==EAGAIN)
							break;
					}
					else{
						puts("Not yet!");
					}
				}
      }
    }
  }

  // Close Sockets and epolls
  free(ep_events);
  close(serv_sock);
  close(epfd);
  return 0;
}