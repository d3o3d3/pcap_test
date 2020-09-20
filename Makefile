all : pcap_test

pcap_test : tcp.h main.c
	gcc -o pcap_test main.c -lpcap

clean :
	rm -f pcap_test