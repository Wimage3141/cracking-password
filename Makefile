OPENSSL_CFLAGS := -I/opt/homebrew/opt/openssl@3/include
OPENSSL_LDFLAGS := -L/opt/homebrew/opt/openssl@3/lib -lcrypto

all: project2

# project2: main.c hash.c hash_functions.c hash.h hash_functions.h
# 	gcc main.c hash.c hash_functions.c -lcrypto -o project2

project2: main.c hash.c hash_functions.c hash.h hash_functions.h
	gcc main.c hash.c hash_functions.c $(OPENSSL_CFLAGS) $(OPENSSL_LDFLAGS) -o project2

test:
	./project2 data/common-passwords.txt data/hashes.txt output.txt
	diff data/expected.txt output.txt