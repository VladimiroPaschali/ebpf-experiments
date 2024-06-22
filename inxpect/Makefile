TARGET := inxpect
SRCS := $(wildcard *.c)
#SRCS :=  $(filter-out inxpect-server.c, $(SRCS)) debug
OBJS := $(SRCS:.c=.o)

cJSON := includes/cJSON
KHEADER:= kperf_/
HELPERS_OBJ := $(KHEADER)/mykperf_helpers.o

.PHONY: all clean
.SILENT: all clean %.o

all: build-cjson $(TARGET) #$(TARGET)_tr

$(TARGET): $(OBJS)
	@echo "Compiling $(TARGET)"
	gcc -g -Wall -O2 -o $@ $(TARGET)-server.o $(TARGET).o $(HELPERS_OBJ) $(cJSON).o -lbpf

$(TARGET)_tr: $(OBJS)
	@echo "Compiling $(TARGET)_tr"
	gcc -g -Wall -O2 -o $@ $(TARGET)-server.o $(TARGET)_tr.o $(HELPERS_OBJ) $(cJSON).o -lbpf

%.o: %.c
	@echo "Compiling $<"
	gcc -g -Wno-unused-function -O2 -I$(KHEADER) -c -o $@ $<

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