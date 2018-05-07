CC=gcc
vpath %.c src
vpath %.h include

OBJS=main.o initrawsock.o
SRCS=$(OBJS:%.o=%.c)
CFLAGS=-g -Wall -I include
LDLIBS=-lpcap
TARGET=main
$(TARGET):$(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LDLIBS)

.PHONY: clean remove
clean:
	@rm *.o
remove:
	@rm main
