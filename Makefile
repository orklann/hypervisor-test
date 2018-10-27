shellcode: shellcode.s
	clang shellcode.s -o shellcode.o
	objdump -d shellcode.o
monitor: monitor.c
	clang -g -O0 -framework Hypervisor monitor.c -o monitor
clean:
	rm -rf monitor monitor.dSYM
