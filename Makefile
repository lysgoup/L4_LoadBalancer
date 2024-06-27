all : client/echo_client.c server/echo_EPLTserv.c src/LoadBalancer.c
	gcc -o lb src/LoadBalancer.c
	gcc -o serv server/echo_EPLTserv.c
	gcc -o clnt client/echo_client.c

debug : LoadBalancer.c
	gcc -o lb src/LoadBalancer.c -DDEBUG

clean : 
	rm lb serv clnt

RST :
	sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP