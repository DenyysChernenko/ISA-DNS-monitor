CC = gcc
CFLAGS = -Wall -Wextra -g
LIBS = -lpcap

TARGET = dns-monitor
OBJECTS = dns-monitor.o arguments-parse.o packet-capture.o domain-file-handle.o 

.PHONY: all clean

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

dns-monitor.o: dns-monitor.c dns-monitor.h arguments-parse.h packet-capture.h domain-file-handle.h
	$(CC) $(CFLAGS) -c dns-monitor.c

arguments-parse.o: arguments-parse.c arguments-parse.h
	$(CC) $(CFLAGS) -c arguments-parse.c

packet-capture.o: packet-capture.c packet-capture.h
	$(CC) $(CFLAGS) -c packet-capture.c

domain-file-handle.o: domain-file-handle.c domain-file-handle.h
	$(CC) $(CFLAGS) -c domain-file-handle.c

clean:
	$(RM) *.o $(TARGET) *.out