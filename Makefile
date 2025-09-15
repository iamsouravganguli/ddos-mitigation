all:
	clang -O2 -target bpf -I/usr/include -I/usr/include/linux -c xdp_ddos.c -o xdp_ddos.o

clean:
	rm -f xdp_ddos.o
