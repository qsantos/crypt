CPPFLAGS := -D_XOPEN_SOURCE=700
CFLAGS := -O3 -std=c99 -Wall -Wextra -Wpedantic -Wformat -Wshadow -Wconversion -Wfloat-equal -Wpadded
LDFLAGS := -O3
TARGETS := crypt generate sort

all: $(TARGETS)

crypt: crypt.o md2.o md4.o md5.o sha1.o sha256.o sha512.o hash.o hmac.o des.o rijndael.o cipher.o
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
