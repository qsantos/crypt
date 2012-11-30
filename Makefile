CFLAGS  = -Wall -Werror -pedantic -std=c99 -O3 -D_XOPEN_SOURCE=700
LDFLAGS = -O3
TARGET  = crypt
SRC     = main.c md2.c md4.c md5.c sha1.c sha256.c sha512.c hash.c hmac.c des.c rijndael.c cipher.c
OBJ     = $(SRC:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	gcc $(LDFLAGS) $^ -o $@

%.o: %.c
	gcc $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o

destroy: clean
	rm -f $(TARGET)

rebuild: destroy all
