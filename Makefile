all:
	clang -O2 -target bpf -c xdp_ddos.c -o xdp_ddos.o

clean:
	rm -f xdp_ddos.o
