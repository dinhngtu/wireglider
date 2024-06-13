CPPFLAGS+=-D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -MMD -MP
CPPFLAGS+=-Iinclude
CFLAGS+=-Wall -Wextra -Wformat=2 -Wshadow -Werror=return-type -std=c11 -fwrapv
CXXFLAGS+=-Wall -Wextra -Wformat=2 -Wshadow -Werror=return-type -std=c++20 -fwrapv

CPPFLAGS+=-pthread
LDLIBS+=-pthread

CPPFLAGS+=-I/lib/modules/$(shell uname -r)/build/usr/include

TDUTIL_ROOT?=$(realpath ../tdutil)
CPPFLAGS+=-I$(TDUTIL_ROOT)/include
LDFLAGS+=-L$(TDUTIL_ROOT)
LDLIBS+=-ltdutil

#LIBURING_ROOT?=$(realpath ../liburing)
#CPPFLAGS+=-I$(LIBURING_ROOT)/src/include

# ./b2 variant=release link=static runtime-link=shared stage
BOOST_ROOT?=$(realpath ../boost_1_85_0)
CPPFLAGS+=-I$(BOOST_ROOT)
LDFLAGS+=-L$(BOOST_ROOT)/stage/lib
LDLIBS+=

CXXOPTS_ROOT?=$(realpath ../cxxopts)
CPPFLAGS+=-I$(CXXOPTS_ROOT)/include

BORINGTUN_ROOT?=$(realpath ../boringtun)
CPPFLAGS+=-I$(BORINGTUN_ROOT)/boringtun/src
LDFLAGS+=-L$(BORINGTUN_ROOT)/target/release
LDLIBS+=-lboringtun

FMT_ROOT?=$(realpath ../fmt)
CPPFLAGS+=-I$(FMT_ROOT)/include
LDFLAGS+=-L$(FMT_ROOT)/build
LDLIBS+=-lfmt

MIMALLOC_ROOT?=$(realpath ../mimalloc)
CPPFLAGS+=-I$(MIMALLOC_ROOT)/include
LDFLAGS+=-L$(MIMALLOC_ROOT)/out/release
LDLIBS+=-lmimalloc

XXHASH_ROOT?=$(realpath ../xxHash)
CPPFLAGS+=-I$(XXHASH_ROOT) -DXXH_INLINE_ALL

# build$ cmake .. -DLIBTINS_BUILD_SHARED=0 -DLIBTINS_ENABLE_CXX11=1
TINS_ROOT?=$(realpath ../libtins)
CPPFLAGS+=-I$(TINS_ROOT)/include
LDFLAGS+=-L$(TINS_ROOT)/build/lib
LDLIBS+=-ltins

ifeq ($(DEBUG), 1)
	CPPFLAGS+=-DDEBUG=1
	CFLAGS+=-O0 -g3 -fno-omit-frame-pointer
	CXXFLAGS+=-O0 -g3 -fno-omit-frame-pointer
else ifeq ($(SANITIZE), 1)
	CPPFLAGS+=-DNDEBUG
	CFLAGS+=-Og -g3 -fsanitize=undefined -fsanitize=address -fno-omit-frame-pointer
	CXXFLAGS+=-Og -g3 -fsanitize=undefined -fsanitize=address -fno-omit-frame-pointer
	ifneq ($(USE_CLANG), 1)
		CFLAGS+=-fanalyzer
		CXXFLAGS+=-fanalyzer
	endif
else
	CPPFLAGS+=-DNDEBUG
	CFLAGS+=-O2 -g3
	CXXFLAGS+=-O2 -g3
	ifeq ($(USE_CLANG), 1)
		CFLAGS+=-flto=thin
		CXXFLAGS+=-flto=thin
		LDFLAGS+=-flto=thin
	else
		CFLAGS+=-flto -fuse-linker-plugin
		CXXFLAGS+=-flto -fuse-linker-plugin
		LDFLAGS+=-flto -fuse-linker-plugin
	endif
endif

ifeq ($(HARDENING), 1)
	CPPFLAGS+=-D_FORTIFY_SOURCE=2
	CFLAGS+=-fstack-protector-strong -fstack-clash-protection -fPIE -fvisibility=hidden
	CXXFLAGS+=-fstack-protector-strong -fstack-clash-protection -fPIE -fvisibility=hidden
	LDFLAGS+=-Wl,-z,now -Wl,-z,relro -pie
	ifeq ($(USE_CLANG), 1)
		CFLAGS+=-fsanitize=safe-stack -fsanitize=cfi
		CXXFLAGS+=-fsanitize=safe-stack -fsanitize=cfi
	endif
endif

TARGETS=\
	wgss \

DEPS=$(wildcard *.d)

all: $(TARGETS)

$(TARGETS): %: %.cpp $(OBJ_MIMALLOC)
	$(LINK.cpp) $(OBJ_MIMALLOC) $< $(filter-out $(OBJ_MIMALLOC),$(filter %.o,$^)) $(LOADLIBES) $(LDLIBS) -o $@

wgss: worker.o netutil.o

clean:
	$(RM) $(TARGETS)
	$(RM) $(OBJECTS)
	$(RM) $(DEPS)
	find . -name '*.[od]' -print -delete

-include $(DEPS)
