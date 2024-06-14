#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#ifdef DEBUG
  #define debug(fn) fn
#else
  #define debug(fn)
#endif

// Before run this code, execute the command below 
// $ sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

#define BUF_SIZE 65536
#define EPOLL_SIZE 50
#define MAX_SERV_CNT 5
#define MAX_CLNT_CNT 1000

enum algorithms{
  RR,
  LEAST_CONN,
  RESOURCE_BASED
};

enum direction{
	CLNT2SERV,
	SERV2CLNT
};

typedef struct _serv_list_node{
  int sock;
  struct in_addr ip;
  u_short port;
  int clnt_cnt;
	struct sockaddr sock_adr;
	float resource_usage; // cpu_usage + ram_usage %
}serv_list_node;

int serv_cnt;
serv_list_node serv_list[MAX_SERV_CNT];

typedef struct _clnt_list_node{
  struct in_addr ip;
  int port;
	int pseudo_port;
}clnt_list_node;

clnt_list_node clnt_list[MAX_CLNT_CNT];
int clnt_cnt;
int forwarding_table[MAX_CLNT_CNT];

typedef enum _TCP_TYPE{
	SYN,
	ACK,
	SYN_ACK,
	FIN,
	DATA
}TCP_TYPE;

// Pseudo header needed for tcp header checksum calculation
struct pseudo_header
{
	uint32_t source_address;
	uint32_t dest_address;
	uint8_t placeholder;
	uint8_t protocol;
	uint16_t tcp_length;
};

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

int add_server_info(int sock, struct in_addr ip, int port)
{
  for(int i=0;i<MAX_SERV_CNT;i++){
    if(serv_list[i].sock == 0){
      serv_list[i].sock = sock;
      serv_list[i].ip = ip;
      serv_list[i].port = port;
      serv_list[i].clnt_cnt = 0;
    }
    break;
  }
  serv_cnt++;
  return 0;
}

void delete_server_node(int sock){
  for(int i=0;i<MAX_SERV_CNT;i++){
    if(serv_list[i].sock == sock){
      memset(&serv_list[i],0,sizeof(serv_list_node));
    }
    break;
  }
  serv_cnt--;
}

// Define checksum function which returns unsigned short value 
unsigned short checksum(uint16_t *buf ,size_t len)
{
	unsigned int sum = 0;
	unsigned short checksum = 0;
	while(len>1){
		sum += *buf;
		buf++;
		len -= 2;
	}
	if(len == 1){
		unsigned short temp = 0;
		*((uint8_t *)&temp)=*(uint8_t*)buf;
		sum += temp;
		len -= 1;
	}
	sum = (sum & 0xffff) + (sum >> 16);
	checksum = ~sum;
	return checksum;
}

void make_pseudo_header(void* temp_c, uint32_t saddr, uint32_t daddr, uint8_t protocol, size_t tcp_len)
{
	struct pseudo_header *temp = (struct pseudo_header *)temp_c;
	temp->source_address = saddr;
	temp->dest_address = daddr;
	temp->placeholder = 0;
	temp->protocol = protocol;
	temp->tcp_length = htons(tcp_len);
}

int check_ip_and_port(char *buffer, struct sockaddr_in lbaddr){
  ssize_t received;
	struct iphdr *synack_ip = (struct iphdr *)buffer;
	struct tcphdr *synack_tcp = (struct tcphdr *)(buffer+sizeof(struct iphdr));	
  if(synack_ip->daddr==lbaddr.sin_addr.s_addr && synack_tcp->dest==lbaddr.sin_port){
		debug(
	  printf("SYN-ACK length: %d\n",received);
	  printf("SYN: %d\n",synack_tcp->syn);
	  printf("ACK: %d\n",synack_tcp->ack);
		printf("FIN: %d\n",synack_tcp->fin);
	  printf("SEQ_num: %u\n",ntohl(synack_tcp->seq));
	  printf("ACK_num: %u\n",ntohl(synack_tcp->ack_seq));
		)
    return 0;
  }
  else return 1;
}

char *nat(char *buffer, int dest_id, struct sockaddr_in lbaddr, enum direction dir){
  struct iphdr *ip = (struct iphdr *)buffer;
	struct tcphdr *tcp = (struct tcphdr *)(buffer+sizeof(struct iphdr));	
	int packet_len = ntohs(ip->tot_len);
	int ip_header_len = (ip->ihl)*4;
	int tcp_len = packet_len - ip_header_len;

	debug(
  printf("[Before] s_ip: %s\n",inet_ntoa(*(struct in_addr *)&(ip->saddr)));
  printf("[Before] d_ip: %s\n",inet_ntoa(*(struct in_addr *)&(ip->daddr)));
  printf("[Before] s_port: %d\n",ntohs(tcp->source));
  printf("[Before] d_port: %d\n",ntohs(tcp->dest));
	);

	ip->saddr = lbaddr.sin_addr.s_addr;
	tcp->source = lbaddr.sin_port;
	if(dir == CLNT2SERV){
		ip->daddr = serv_list[dest_id].ip.s_addr;
  	tcp->dest = serv_list[dest_id].port;
	}
	else{
		ip->daddr = clnt_list[dest_id].ip.s_addr;
  	tcp->dest = clnt_list[dest_id].port;
	}
  

	debug(
	printf("[After] s_ip: %s\n",inet_ntoa(*(struct in_addr *)&(ip->saddr)));
  printf("[After] d_ip: %s\n",inet_ntoa(*(struct in_addr *)&(ip->daddr)));
  printf("[After] s_port: %d\n",ntohs(tcp->source));
  printf("[After] d_port: %d\n",ntohs(tcp->dest));
	);

	ip->check = 0;
	tcp->check = 0;
	unsigned char *temp_c = (unsigned char *)malloc(sizeof(struct pseudo_header)+tcp_len);
	make_pseudo_header(temp_c, lbaddr.sin_addr.s_addr, ip->daddr, 6, tcp_len);
	memcpy(temp_c+sizeof(struct pseudo_header),tcp,tcp_len);
	tcp->check = checksum((uint16_t *)temp_c, sizeof(struct pseudo_header)+tcp_len);
	free(temp_c);
  ip->check = checksum((uint16_t *)ip, sizeof(struct iphdr));
  return buffer;
}

TCP_TYPE check_type(char *buffer){
	struct iphdr *ip = (struct iphdr *)buffer;
	struct tcphdr *tcp = (struct tcphdr *)(buffer+sizeof(struct iphdr));	
	if(tcp->syn==1 && tcp->ack==0) return SYN;
	else if(tcp->syn==1 && tcp->ack==1) return SYN_ACK;
	else if(tcp->fin==1) return FIN;
	else if(tcp->ack==1) return ACK;
	else return DATA;
}

void add_new_clnt(clnt_list_node *clnt_node, char *buffer){
	struct iphdr *ip = (struct iphdr *)buffer;
	struct tcphdr *tcp = (struct tcphdr *)(buffer+sizeof(struct iphdr));	
	srand(time(0));
	clnt_node->ip.s_addr = ip->saddr;
	clnt_node->port = tcp->source;
	clnt_node->pseudo_port = rand() % 16386 + 49152;
	clnt_cnt++;
}

// TODO select server
int select_serv(int algo){
	return 0;
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
  if(argc != 5){
    printf("Usage : %s <LB IP> <port for server> <port for clients> <algorithm num>\n[algorithm num]\n- RR:0\n- Least Connection:1\n- Resource Based: 2\n",argv[0]);
    exit(1);
  }

  enum algorithms selected_algo = atoi(argv[4]);
  char *selected_algo_string = make_algo_string(selected_algo);
  printf("Selected Algorithm: %s\n",selected_algo_string);
  free(selected_algo_string);

  // Open Socket for Server(TCP)
  lb_sock=socket(PF_INET, SOCK_STREAM, 0);
	memset(&lb_adr, 0, sizeof(lb_adr));
	lb_adr.sin_family=AF_INET;
	lb_adr.sin_addr.s_addr=htonl(INADDR_ANY);
	lb_adr.sin_port=htons(atoi(argv[2]));

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

  // Init Server List : 연결된 서버 목록
  serv_cnt = 0;
  for(int i=0;i<MAX_SERV_CNT;i++){
    memset(serv_list,0,sizeof(serv_list_node));
  }

  // Open Raw Socket
  int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (raw_sock == -1)
	{
		perror("raw socket");
        exit(EXIT_FAILURE);
	}

  // LB IP and Port for Client
	struct sockaddr_in lbaddr;
	lbaddr.sin_family = AF_INET;
	lbaddr.sin_port = htons(atoi(argv[3]));
	if (inet_pton(AF_INET, argv[1], &lbaddr.sin_addr) != 1)
	{
		perror("Source IP configuration failed\n");
		exit(EXIT_FAILURE);
	}

  // Tell the kernel that headers are included in the packet
	int one = 1;
	const int *val = &one;
	if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) == -1)
	{
		perror("setsockopt(IP_HDRINCL, 1)");
		exit(EXIT_FAILURE);
	}

  // Add Raw Socket to Epoll
  setnonblockingmode(raw_sock);
	event.events=EPOLLIN;
	event.data.fd=raw_sock;	
	epoll_ctl(epfd, EPOLL_CTL_ADD, raw_sock, &event);

  // Init Client List : 연결된 클라이언트 목록
  clnt_cnt = 0;
  for(int i=0;i<MAX_CLNT_CNT;i++){
    memset(&clnt_list[i],0,sizeof(clnt_list_node));
  }

	// Init Forwarding Table : 서버-클라이언트 연결 리스트(클라이언트,서버)
  for(int i=0;i<MAX_CLNT_CNT;i++){
    forwarding_table[i] = -1;
  }

	// TODO init_health_check_timer
  
  while(1){
    // Server Epoll Wait
    event_cnt=epoll_wait(epfd, ep_events, EPOLL_SIZE, 0);
		if(event_cnt == 0) continue;
    if(event_cnt==-1){
      puts("epoll_wait() error");
			break;
    }
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
          // Connection complete
          send(serv_sock,&selected_algo,sizeof(int),MSG_NOSIGNAL);

          // Update Server List
          u_short server_port;
          recv(serv_sock,&server_port,sizeof(u_short),0);
          printf("server_port: %d\n",server_port);
          add_server_info(serv_sock,serv_adr.sin_addr,htons(server_port));
          printf("Connected Server: %d [%s:%d]\nServer count: %d\n", serv_sock,inet_ntoa(*(struct in_addr *)&(serv_adr.sin_addr)),ntohs(serv_adr.sin_port),serv_cnt);

          setnonblockingmode(serv_sock);
          event.events=EPOLLIN|EPOLLET;
          event.data.fd=serv_sock;
          epoll_ctl(epfd, EPOLL_CTL_ADD, serv_sock, &event);
        }
      }
			else if(ep_events[i].data.fd==raw_sock){
				int source_id, dest_id;
				int received = recv(raw_sock,buf,BUF_SIZE,0);
				int block = check_ip_and_port(buf, lbaddr);
				char *new_packet = NULL;
				if(block == 1 || serv_cnt == 0) continue;
				TCP_TYPE type = check_type(buf);
				switch(type){
					case SYN:
						// Update client list and forwarding table
						if(clnt_cnt == MAX_CLNT_CNT) continue;
						for(int i=0;i<MAX_CLNT_CNT;i++){
							if(clnt_list[i].port == 0){
								source_id = i;
								add_new_clnt(&clnt_list[source_id],buf);
								forwarding_table[source_id] = select_serv(selected_algo);
								dest_id = forwarding_table[source_id];
								printf("--------NAT--------\n");
								new_packet = nat(buf,dest_id,lbaddr,CLNT2SERV);
								printf("-------------------\n");
								sendto(raw_sock, new_packet, received, 0, &(serv_list[dest_id].sock_adr), sizeof(struct sockaddr));
								break;
							}
						}
						break;
					case SYN_ACK:

						// for(int i=0;i<MAX_CLNT_CNT;i++){
						// 	if(forwardig_table[i].
						// }
						break;
					case ACK:
						break;
					case FIN:
						break;
				}
			}
      else{
        while(1){
					str_len=read(ep_events[i].data.fd, buf, BUF_SIZE);
					if(str_len==0){
						epoll_ctl(epfd, EPOLL_CTL_DEL, ep_events[i].data.fd, NULL);
						close(ep_events[i].data.fd);

            // Delete from Forwarding Table
            for(int i=0;i<MAX_CLNT_CNT;i++){
              if(serv_list[forwarding_table[i]].sock == ep_events[i].data.fd){
                forwarding_table[i] = -1;
              }
            }
            // Update Server List
            delete_server_node(ep_events[i].data.fd);
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
  close(raw_sock);
  close(epfd);
  return 0;
}