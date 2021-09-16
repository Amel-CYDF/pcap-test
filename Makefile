all: pcap-test

pcap-test:
	gcc -o pcap-test pcap-test.c -lpcap

clean:
	rm -f pcap-test
