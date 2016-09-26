CPPFLAGS :=
CFLAGS := -O3 -std=c99 -Wall -Wextra -Wpedantic -Wformat -Wshadow -Wconversion -fopenmp
LDFLAGS := -O3 -fopenmp
TARGETS := crypt benchmark bruteforce generate sort

DIGESTS := md2.o md4.o md5.o sha1.o sha256.o sha512.o
SIMD := x86.o mmx.o sse2.o avx2.o avx512.o

all: $(TARGETS)

crypt: crypt.o $(DIGESTS) hash.o hmac.o des.o rijndael.o cipher.o
benchmark: benchmark.o argparse.o util.o $(DIGESTS) $(SIMD)
bruteforce: bruteforce.o argparse.o util.o $(SIMD)
generate: generate.o md5.o
sort: sort.o argparse.o util.o

# handle include dependencies
-include $(wildcard *.d)
%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<
	$(CC) $(CFLAGS) $(CPPFLAGS) -MM -o $*.d $<

clean:
	rm -f *.o *.d

destroy: clean
	rm -f $(TARGETS)

rebuild: destroy all

.PHONY: all clean destroy rebuild
