CC := x86_64-w64-mingw32-gcc
CXX := x86_64-w64-mingw32-g++
LD := x86_64-w64-mingw32-ld
CFLAGS := -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2
CCLDFLAGS := -Wl,-Tsrc/linker.ld,--no-seh -DC2

S_SRCS := src/adjuststack.asm src/chkstk_ms.asm src/GateTrampolin.asm 
C_SRCS := src/ApiResolve.c src/HandleKatzPIC.c src/Misc.c src/HandleTools.c src/DumpTools.c src/RecycledGate.c
OBJS := $(patsubst src/%.asm,%.o,$(S_SRCS)) $(patsubst src/%.c,%.o,$(C_SRCS))

all: bin/HandleKatzPIC.exe bin/HandleKatz.bin bin/loader.exe

bin/HandleKatzPIC.exe: $(OBJS)
	mkdir -p $(@D)
	$(LD) -s $^ -o $@

bin/HandleKatz.bin: bin/HandleKatzPIC.exe
	objcopy -j .text -O binary $< $@

loader/HandleKatz.h: loader/HandleKatz.h.prefix bin/HandleKatz.bin
	(                                                        \
		set -e;                                          \
		cat loader/HandleKatz.h.prefix;                  \
		base64 bin/HandleKatz.bin | xargs -i echo '"{}"';\
		echo ';'                                         \
	) > $@.t
	mv $@.t $@

bin/loader.exe: loader/loader.cpp loader/HandleKatz.h
	mkdir -p $(@D)
	$(CXX) -s -o $@ $< -lcrypt32

%.o: src/%.asm
	nasm -f win64 $< -o $@

%.o: src/%.c
	$(CC) $< $(CFLAGS) -c -o $@ $(CCLDFLAGS)

.PHONY: clean
clean:
	rm -rf $(OBJS) \
		bin/HandleKatzPIC.exe bin/HandleKatz.bin \
		loader/HandleKatz.h bin/loader.exe
