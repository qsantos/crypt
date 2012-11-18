CFLAGS  = -Wall -Werror -pedantic -std=c99 -O3
LDFLAGS = -O3
TARGET  = crypt
SRC     = aes.c cipher.c des.c digest.c main.c md2.c md4.c md5.c sha1.c sha256.c sha512.c
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
