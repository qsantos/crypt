CPPFLAGS :=
CFLAGS := -O3 -std=c99 -Wall -Wextra -Wpedantic -Wformat -Wshadow -Wconversion -fopenmp
LDFLAGS := -O3 -fopenmp
TARGETS := crypt benchmark bruteforce generate sort

all: $(TARGETS)

crypt: crypt.o md2.o md4.o md5.o sha1.o sha256.o sha512.o hash.o hmac.o des.o rijndael.o cipher.o
benchmark: benchmark.o util.o md4.o md5.o sha1.o md4_simd.o md5_simd.o sha1_simd.o
bruteforce: bruteforce.o util.o md5_simd.o
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
