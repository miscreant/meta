CFLAGS=-I../../include -Wall -O3 -pedantic -std=c99

libmiscreant = ../../target/release/libmiscreant.a

all: ffi_test

clean:
	rm -f *.o ffi_test

$(libmiscreant):
	cd ../.. && cargo build --no-default-features --features=staticlib --release

ffi_test: ffi_test.o $(libmiscreant)
	$(CC) $(LDFLAGS) -o ffi_test ffi_test.o $(libmiscreant)
