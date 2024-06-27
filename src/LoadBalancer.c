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
#include <limits.h>

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

int recent_serv_id;

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
	int resource_usage; // cpu_usage + ram_usage %
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
int forwarding_table[MAX_CLNT_CNT][2];

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
			printf("New Server[ID:%d, Sock:%d, Port:%d] is added(Server Count: %d)\n",i,serv_list[i].sock,ntohs(port),serv_cnt);
   	  break;
    }
  }
  serv_cnt++;
  return 0;
}

void delete_server_node(int id){
	serv_cnt--;
	printf("Server[ID:%d, Sock:%d] is closed(Server Count: %d)\n",id,serv_list[id].sock,serv_cnt);
	memset(&serv_list[id],0,sizeof(serv_list_node));
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
	struct iphdr *ip = (struct iphdr *)buffer;
	struct tcphdr *tcp = (struct tcphdr *)(buffer+sizeof(struct iphdr));	
  if(ip->daddr==lbaddr.sin_addr.s_addr && tcp->dest==lbaddr.sin_port){
		debug(
			printf("Src Port: %d\n",ntohs(tcp->source));
			printf("Dest Port: %d\n",ntohs(tcp->dest));
			printf("SYN: %d\n",tcp->syn);
			printf("ACK: %d\n",tcp->ack);
			printf("FIN: %d\n",tcp->fin);
			printf("SEQ_num: %u\n",ntohl(tcp->seq));
			printf("ACK_num: %u\n",ntohl(tcp->ack_seq));
		)
    return CLNT2SERV;
  }
	else if(ip->daddr==lbaddr.sin_addr.s_addr){
		for(int i=0;i<MAX_CLNT_CNT;i++){
			if(clnt_list[i].pseudo_port==tcp->dest){
				debug(
					printf("Src Port: %d\n",ntohs(tcp->source));
					printf("Dest Port: %d\n",ntohs(tcp->dest));
					printf("SYN: %d\n",tcp->syn);
					printf("ACK: %d\n",tcp->ack);
					printf("FIN: %d\n",tcp->fin);
					printf("SEQ_num: %u\n",ntohl(tcp->seq));
					printf("ACK_num: %u\n",ntohl(tcp->ack_seq));
				)
				return SERV2CLNT;
			}
		}
		return -1;
	}
  else return -1;
}

char *nat(char *buffer, int source_id, int dest_id, struct sockaddr_in lbaddr, enum direction dir){
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
	if(dir == CLNT2SERV){
		ip->daddr = serv_list[dest_id].ip.s_addr;
  	tcp->dest = serv_list[dest_id].port;
		tcp->source = clnt_list[source_id].pseudo_port;
	}
	else{
		ip->daddr = clnt_list[dest_id].ip.s_addr;
  	tcp->dest = clnt_list[dest_id].port;
		tcp->source = lbaddr.sin_port;
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


int select_serv(int algo){
	switch(algo){
		case RR:
			if(recent_serv_id == -1){
				for(int i=0;i<MAX_SERV_CNT;i++){
					if(serv_list[i].sock != 0){
						recent_serv_id = i;
						return i;
					}
				}
			}
			else{
				while(1){
					recent_serv_id++;
					if(recent_serv_id==MAX_SERV_CNT) recent_serv_id=0;
					if(serv_list[recent_serv_id].sock != 0){
						return recent_serv_id;
					}
				}
			}
			break;
		case LEAST_CONN:
			printf("Connection List\n");
			int min_clnt = MAX_CLNT_CNT;
			int min_index;
			int count_down = serv_cnt;
			for(int i=0;i<MAX_CLNT_CNT;i++){
				if(serv_list[i].sock != 0){
					printf("[ID:%d] %d\n",i,serv_list[i].clnt_cnt);
					count_down--;
					if(serv_list[i].clnt_cnt < min_clnt){
						min_clnt = serv_list[i].clnt_cnt;
						min_index = i;
					}
				}
				if(count_down == 0) break;
			}
			return min_index;
		case RESOURCE_BASED:
			printf("Resource Usages\n");
			int min_resource = INT_MAX;
			count_down = serv_cnt;
			for(int i=0;i<MAX_CLNT_CNT;i++){
				if(serv_list[i].sock != 0){
					printf("[ID:%d] %d\n",i,serv_list[i].resource_usage);
					count_down--;
					if(serv_list[i].resource_usage < min_resource){
						min_resource = serv_list[i].resource_usage;
						min_index = i;
					}
				}
				if(count_down == 0) break;
			}
			return min_index;
	}
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

	int optval = 1;
	if (setsockopt(lb_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1) {
		perror("setsockopt(SO_REUSEADDR)");
		close(lb_sock);
		exit(EXIT_FAILURE);
	}

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
    forwarding_table[i][0] = -1;
		forwarding_table[i][1] = -1;
  }
  
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
          add_server_info(serv_sock,serv_adr.sin_addr,htons(server_port));
          debug(printf("Connected Server: %d [%s:%d]\nServer count: %d\n", serv_sock,inet_ntoa(*(struct in_addr *)&(serv_adr.sin_addr)),ntohs(serv_adr.sin_port),serv_cnt);)

          setnonblockingmode(serv_sock);
          event.events=EPOLLIN|EPOLLET;
          event.data.fd=serv_sock;
          epoll_ctl(epfd, EPOLL_CTL_ADD, serv_sock, &event);
        }
      }
			else if(ep_events[i].data.fd==raw_sock){
				int source_id = -1;
				int dest_id;
				int received = recv(raw_sock,buf,BUF_SIZE,0);
				enum direction dir = check_ip_and_port(buf, lbaddr);
				struct iphdr *ip = (struct iphdr *)buf;
				struct tcphdr *tcp = (struct tcphdr *)(buf+sizeof(struct iphdr));	
				char *new_packet = NULL;
				if(dir == -1 || serv_cnt == 0) continue;
				TCP_TYPE type = check_type(buf);
				if(dir==CLNT2SERV){
					for(int j=0;j<MAX_CLNT_CNT;j++){
						if(clnt_list[j].port==tcp->source){
							source_id = j;
							break;
						}
					}
					// There is no information about source in may be SYN
					if(source_id<0){
						if(type!=SYN || clnt_cnt==MAX_CLNT_CNT) continue;
						// Update client list and forwarding table
						for(int j=0;j<MAX_CLNT_CNT;j++){
							if(clnt_list[j].port == 0){
								source_id = j;
								add_new_clnt(&clnt_list[source_id],buf);
								forwarding_table[source_id][0] = select_serv(selected_algo);
								forwarding_table[source_id][1] = 2;
								serv_list[forwarding_table[source_id][0]].clnt_cnt++;
								printf("New Client[ID:%d] is connected to Server[ID:%d]\n",source_id,forwarding_table[source_id][0]);
								break;
							}
						}
					}
					else if(type == FIN){
						forwarding_table[source_id][1] = 1;
					}
					dest_id = forwarding_table[source_id][0];
					debug(printf("--------NAT--------\n");)
					new_packet = nat(buf,source_id,dest_id,lbaddr,dir);
					debug(printf("-------------------\n");)
					sendto(raw_sock, new_packet, received, 0, &(serv_list[dest_id].sock_adr), sizeof(struct sockaddr));
					if(type == ACK && forwarding_table[source_id][1]==1){
						printf("Client[ID:%d] is disconnected from Server[ID:%d]\n",source_id,forwarding_table[source_id][0]);
						serv_list[dest_id].clnt_cnt--;
						forwarding_table[source_id][0]==-1;
						forwarding_table[source_id][1]==-1;
						memset(&clnt_list[source_id],0,sizeof(clnt_list_node));
						clnt_cnt--;
					}
				}
				else if(dir == SERV2CLNT){
					for(int j=0;j<MAX_CLNT_CNT;j++){
						if(clnt_list[j].pseudo_port==tcp->dest){
							dest_id = j;
							source_id = forwarding_table[j][0];
							break;
						}
					}
					if(type==FIN){
						forwarding_table[dest_id][1] = 1;
					}
					debug(printf("--------NAT--------\n");)
					new_packet = nat(buf,source_id,dest_id,lbaddr,dir);
					debug(printf("-------------------\n");)
					struct sockaddr_in daddr;
					daddr.sin_family = AF_INET;
					daddr.sin_port = tcp->dest;
					daddr.sin_addr.s_addr = ip->daddr;
					sendto(raw_sock, new_packet, received, 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr_in));
					if(type==ACK && forwarding_table[dest_id][1]==-1){
						printf("Client[ID:%d] is disconnected from Server[ID:%d]\n",dest_id,forwarding_table[dest_id][0]);
						serv_list[source_id].clnt_cnt--;
						forwarding_table[dest_id][0]==-1;
						forwarding_table[dest_id][1]==-1;
						memset(&clnt_list[dest_id],0,sizeof(clnt_list_node));
						clnt_cnt--;
					}
					break;
				}
			}
      else{
				int server_id, received_usage;
				for(int j=0;j<MAX_SERV_CNT;j++){
					if(serv_list[j].sock==ep_events[i].data.fd){
						server_id = j;
						break;
					}
				}
        while(1){
					str_len=read(ep_events[i].data.fd, &received_usage, sizeof(int));
					if(str_len==0){
						epoll_ctl(epfd, EPOLL_CTL_DEL, ep_events[i].data.fd, NULL);
						close(ep_events[i].data.fd);
            // Delete from Forwarding Table
            for(int j=0;j<MAX_CLNT_CNT;j++){
              if(forwarding_table[j][0] == server_id){
								printf("Client[ID:%d] is disconnected from Server[ID:%d]\n",j,forwarding_table[j][0]);
								memset(&clnt_list[j],0,sizeof(clnt_list_node));
								clnt_cnt--;
                forwarding_table[j][0] = -1;
								forwarding_table[j][1] = -1;
              } 
            }
            // Update Server List
            delete_server_node(server_id);
						break;
					}
					else if(str_len<0){
						if(errno==EAGAIN)
							break;
					}
					else{
						// Health check
						printf("Received health check form Server[ID:%d]: %d\n",server_id,received_usage);
						serv_list[server_id].resource_usage = received_usage;
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