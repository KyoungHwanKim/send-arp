all: send-arp

send-arp: main.o arphdr.o ethhdr.o ip.o mac.o
	g++ -o send-arp main.o arphdr.o ethhdr.o ip.o mac.o -lpcap

clean:
	rm -f send-arp *.o
