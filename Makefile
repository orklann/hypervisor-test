shellcode:
	clang shellcode.s -o shellcode.o
	objdump -d shellcode.o
monitor:
	clang -g -O0 -framework Hypervisor monitor.c -o monitor
clean:
	rm -rf monitor monitor.dSYM
