make:
	nasm -f win64 src/adjuststack.asm -o adjuststack.o
	nasm -f win64 src/chkstk_ms.asm -o chkstk_ms.o
	nasm -f win64 src/syscalls.asm -o syscalls.o
	x86_64-w64-mingw32-gcc src/ApiResolve.c -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o ApiResolve.o -Wl,-Tlinker.ld,--no-seh -DC2
	x86_64-w64-mingw32-gcc src/HandleKatzPIC.c -masm=intel -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o HandleKatzPIC.o -Wl,-Tlinker.ld,--no-seh -DC2
	x86_64-w64-mingw32-gcc src/Misc.c -masm=intel -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o Misc.o -Wl,-Tlinker.ld,--no-seh -DC2
	x86_64-w64-mingw32-gcc src/HandleTools.c -masm=intel -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o HandleTools.o -Wl,-Tlinker.ld,--no-seh -DC2
	x86_64-w64-mingw32-gcc src/DumpTools.c -masm=intel -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o DumpTools.o -Wl,-Tlinker.ld,--no-seh -DC2
	x86_64-w64-mingw32-ld -s adjuststack.o ApiResolve.o Misc.o HandleKatzPIC.o HandleTools.o DumpTools.o syscalls.o chkstk_ms.o -o bin/HandleKatzPIC.exe

clean:
	rm *.o