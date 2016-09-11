CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -Wformat-security -Wshadow -Wconversion -Wfloat-equal -Winline -Wvector-operation-performance -Wpadded -std=c99 -O3 -D_POSIX_C_SOURCE -D_XOPEN_SOURCE=700
LDFLAGS := -O3
TARGETS := crypt

all: $(TARGETS)

crypt: main.o md2.o md4.o md5.o sha1.o sha256.o sha512.o hash.o hmac.o des.o rijndael.o cipher.o
	$(CC) $(LDFLAGS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o

destroy: clean
	rm -f $(TARGETS)

rebuild: destroy all

.PHONY: all clean destroy rebuild
