#CXX = g++
CPPFILES    := $(wildcard *.cpp)
RM          := rm -rf
CXXFLAGS    += -std=c++1y  -g -fPIC -D_REENTRANT -Wall
CFLAGS      += -g -fPIC
SOVER       := 0.0.0
LIBNAME     := fwupgrade
LIBNAMEFULL := lib$(LIBNAME).so.$(SOVER)
LDFLAGS     := -lz -lm -lpthread
#OBJS        := $(patsubst %.c,%.o,$(wildcard *.c))
#OBJS        := $(patsubst %.c,%.o,$(wildcard *.c)) $(CPPFILES:.cpp=.o)
CFILES      := aml_upgrade.c backed_block.c bootloader_message.c mfrlib.c output_file.c sparse.c sparse_crc32.c sparse_err.c
OBJS        := aml_upgrade.o backed_block.o bootloader_message.o mfrlib.o output_file.o sparse.o sparse_crc32.o sparse_err.o $(CPPFILES:.cpp=.o)


ifneq (, $(findstring -DAVB, $(CFLAGS)))
    CFILES += bootloader_avb.c avb_crc32.c
    OBJS += bootloader_avb.o avb_crc32.o
endif

ifdef USE_IARM_IMPL
    OBJS += mfr_wifi_api.o
    CFILES += mfr_wifi_api.c
endif
BINNAME     := mfrUtil
BINOBJS     := ut_mfrlib.o

all: mfrUtil library

mfrUtil: $(BINOBJS) library
	@echo "Building $(BINNAME) ...."
	$(CC) -o $(BINNAME) $(BINOBJS) -Wl,-rpath-link=${PWD} -L. $(LIBNAMEFULL) $(LDFLAGS)

library: $(OBJS)
	@echo "Building $(LIBNAMEFULL) ...."
	$(CC) -shared -Wl,-soname,lib$(LIBNAME).so -o $(LIBNAMEFULL) $(OBJS)

objects: $(CFILES)
	@echo "Compiling ...."
	$(CC) -c $< $(CFLAGS) $(CFILES)

install: $(LIBNAMEFULL) $(BINNAME)
	@echo "Installing files in $(DESTDIR) ..."
	install -d $(DESTDIR)
	install -m 0755 $< $(DESTDIR)

clean:
	@echo "Make clean ..."
	rm -f *.o *.so *.so.$(SOVER) $(BINNAME)
