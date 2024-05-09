TARGET := inxpect
SRCS := $(wildcard *.c)
OBJS := $(SRCS:.c=.o)

cJSON := includes/cJSON
KHEADER:= kperf_
HELPERS_OBJ := $(KHEADER)/mykperf_helpers.o

.PHONY: all clean
.SILENT: all clean %.o

all: build-cjson $(TARGET)

$(TARGET): $(OBJS)
	@echo "Compiling $(TARGET)"
	gcc -g -Wall -O2 -o $@ $^ $(HELPERS_OBJ) $(cJSON).o -lbpf

%.o: %.c
	@echo "Compiling $<"
	gcc -g -Wall -O2 -I$(KHEADER) -c -o $@ $<

build-cjson:
	@echo "Building cJSON"
	gcc -g -Wall -O2 -I$(cJSON) -c -o $(cJSON).o $(cJSON).c

install:
	@echo "Installing $(TARGET)"
	install -m 755 $(TARGET).o /usr/bin/$(TARGET)

clean:
	rm -f *.o
	rm -f $(TARGET)
	rm -f $(cJSON).o