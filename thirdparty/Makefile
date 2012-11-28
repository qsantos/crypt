CFLAGS  = -Wall -Wextra -Werror -pedantic -ansi -std=c99 -O3
TARGETS = des_arrays_start_at_0 aes_sbox

all: $(TARGETS)

%: %.c
	gcc $(CFLAGS) $< -o $@

clean:
	rm -f *.o

destroy: clean
	rm $(TARGETS)

rebuild: destroy all
