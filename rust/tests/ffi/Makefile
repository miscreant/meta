CFLAGS=-I../../include -Wall -O3 -pedantic -std=c99

all: ffi_test

clean:
	rm -f *.o ffi_test

ffi_test: ffi_test.o
	$(CC) $(LDFLAGS) -lc -o ffi_test ffi_test.o ../../target/release/libmiscreant.a
