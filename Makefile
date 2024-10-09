CC = gcc
CFLAGS = -Wall -Wextra -g
LIBS = -lpcap

TARGET = dns-monitor
OBJECTS = dns-monitor.o arguments-parse.o

.PHONY: all clean

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

dns-monitor.o: dns-monitor.c dns-monitor.h arguments-parse.h
	$(CC) $(CFLAGS) -c dns-monitor.c

arguments-parse.o: arguments-parse.c arguments-parse.h
	$(CC) $(CFLAGS) -c arguments-parse.c

clean:
	$(RM) *.o $(TARGET) *.out