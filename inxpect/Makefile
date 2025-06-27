TARGET := inxpect
SRCS := $(wildcard *.c)
#SRCS :=  $(filter-out inxpect-server.c, $(SRCS)) debug
OBJS := $(SRCS:.c=.o)

KHEADER:= kperf_
HELPERS_OBJ := $(KHEADER)/mykperf_helpers.o

.PHONY: all clean
.SILENT: all clean %.o

all: $(TARGET)

$(TARGET): $(OBJS)
	@echo "Compiling $(TARGET)"
	gcc -g -Wall -O2 -o $@ $^ $(HELPERS_OBJ) -lbpf

%.o: %.c
	@echo "Compiling $<"
	gcc -g -Wno-unused-function -O2 -I$(KHEADER) -c -o $@ $<

install:
	@echo "Installing $(TARGET)"
	install -m 755 $(TARGET).o /usr/bin/$(TARGET)

clean:
	rm -f *.o
	rm -f $(TARGET)