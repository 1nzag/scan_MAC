all: scan_mac

scan_mac: arp_lib.o main.o
	gcc -o scan_mac arp_lib.o main.o -lpcap

arp_lib.o: arp_lib.c arp_lib.h
	gcc -c -o arp_lib.o arp_lib.c -lpcap

main.o: main.c arp_lib.h
	gcc -c -o main.o main.c

clean:
	rm main.o arp_lib.o
