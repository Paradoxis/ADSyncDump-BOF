all: bof64 bof32

bof64:
	x86_64-w64-mingw32-gcc -c adsyncdump.c -o adsyncdump.x64.o -Wno-int-conversion -Wno-discarded-qualifiers -Wno-incompatible-pointer-types
	strip --strip-unneeded adsyncdump.x64.o

bof32:
	i686-w64-mingw32-gcc -c adsyncdump.c -o adsyncdump.x86.o -Wno-int-conversion -Wno-discarded-qualifiers -Wno-incompatible-pointer-types
	strip --strip-unneeded adsyncdump.x86.o

clean:
	rm -f adsyncdump.x64.o adsyncdump.x86.o
