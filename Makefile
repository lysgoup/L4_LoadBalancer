all : echo_client.c echo_EPLTserv.c LoadBalancer.c
	gcc -o lb LoadBalancer.c
	gcc -o serv echo_EPLTserv.c
	gcc -o clnt echo_client.c

debug : LoadBalancer.c
	gcc -o lb LoadBalancer.c -DDEBUG

clean : 
	rm lb serv clnt

RST :
	sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP