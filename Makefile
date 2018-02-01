CXX = gcc
EXE = reverset
SOURCES = $(wildcard src/*.c src/arch/*.c src/arch/x86/*.c src/arch/x86_64/*.c src/file/elf/*.c)
OBJS = $(SOURCES:.c=.o)
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S), Linux) #LINUX
	ECHO_MESSAGE = "Linux"
	CXXFLAGS = -g
	CFLAGS = $(CXXFLAGS)
endif

.c.o:
	$(CXX) $(CXXFLAGS) -c -o $@ $<

all: $(EXE)
	@echo Build complete for $(ECHO_MESSAGE)

$(EXE): $(OBJS)
	$(CXX) -o $(EXE) $(OBJS) $(CXXFLAGS) $(LIBS)

clean:
	rm $(EXE) $(OBJS)
