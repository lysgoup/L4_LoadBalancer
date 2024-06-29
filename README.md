# L4_LoadBalancer
This is a simple project that makes a Level 4 load balancer. This load balancer provide three distributing algorithms. When running the load balancer, users can select an algorithm using the numbers in parentheses.
<br>
1. Round Robin(0)
2. Least Connecntion(1)
3. Resources Based(2)
<br>

With this load balancer, all packets exchanged between the server and the client travel through the load balancer. Servers can be added or removed while the load balancer is running, and when a server is removed, clients connected to that server are disconnected.<br>
<br>
This program uses raw sockets inside the load balancer to perform NAT, while servers and clients use TCP sockets.
The load balancer creates an additional TCP connection to each server for health checks.

## Required Environment
You can build and execute this project in Linux System. 

## How to build
- Use Makefile
```
$ make
```
This makefile creates executables named lb, serv, and clnt. You can delete this executables by `make clean`<br>
If you use `make debug` command, only a loadbalancer source code will be compiled including debuging lines.

## How to run
1. Drop TCP RST Packet
```
$ sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
```
2. Run Load Balancer
```
$ ./lb <LB IP> <Port for Server> <Port for Client> <Algorithm Number>
```
- LB IP : IP address of the load balancer
- Port for Server : Port number of TCP Connection with servers for health check
- Port for Client : Port number of Raw Socket which clients can use for connecting with server
- Algorithm Number : Algorithm which the load balancer will use for distribute connecntion requests to many server.
3. Run Server
```
$ ./serv <LB IP> <LB Port> <Port>
```
- LB IP : IP address of Load Balancer
- LB Port : Port number for health check connection
- Port : Port number for client connections

By default, the maximum number of servers is 5, but you can change it by modifying the MAX_SERV_CNT value in the LoadBalancer code.
4. Run Client
```
$ ./clnt <IP> <Port>
```
- IP : IP Address of the Load Balancer
- Port : Port number for client connection in Load Balancer

By default, the maximum number of clients is 1000, but you can change it by modifying the MAX_CLNT_CNT value in the LoadBalancer code.