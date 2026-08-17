CC = gcc

CFLAGS = -g -std=gnu99 -Wall -Wextra -Werror -Wfatal-errors -pedantic $(IFLAGS)

INCLUDES = $(shell echo *.h)

all: sniffer unit_tests

%.o: %.c $(INCLUDES)
	$(CC) $(CFLAGS) -c $< -o $@

sniffer: sniffer.o capture.o parser.o detector.o output.o
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS) -lpcap

unit_tests: unit_test.o capture.o parser.o detector.o output.o
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS) -lpcap

clean:
	rm -f sniffer unit_tests *.o