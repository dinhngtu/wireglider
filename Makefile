CPPFLAGS+=-D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -MMD -MP
CPPFLAGS+=-Iinclude
CFLAGS+=-Wall -Wextra -Wformat=2 -Werror=shadow -Werror=return-type -std=c11 -fwrapv
CXXFLAGS+=-Wall -Wextra -Wformat=2 -Werror=shadow -Werror=return-type -std=c++20 -fwrapv -fconcepts-diagnostics-depth=2

CPPFLAGS+=-pthread
LDLIBS+=-pthread

# NOTE: customize kernel header include paths if needed
CPPFLAGS+=-I/lib/modules/$(shell uname -r)/build/usr/include

# NOTE: customize processor features as desired
CFLAGS+=-march=native
CXXFLAGS+=-march=native

# make
TDUTIL_ROOT?=$(realpath ../tdutil)
CPPFLAGS+=-I$(TDUTIL_ROOT)/include
LDFLAGS+=-L$(TDUTIL_ROOT)
LDLIBS+=-ltdutil

LIBURING_ROOT?=$(realpath ../liburing)
CPPFLAGS+=-I$(LIBURING_ROOT)/src/include
LDFLAGS+=-L$(LIBURING_ROOT)/src
LDLIBS+=-l:liburing.a

# ./b2 variant=release link=static runtime-link=shared stage
BOOST_ROOT?=$(realpath ../boost_1_85_0)
CPPFLAGS+=-I$(BOOST_ROOT)
LDFLAGS+=-L$(BOOST_ROOT)/stage/lib
LDLIBS+=

CXXOPTS_ROOT?=$(realpath ../cxxopts)
CPPFLAGS+=-I$(CXXOPTS_ROOT)/include

# cargo build --lib --release --features "device ffi-bindings"
BORINGTUN_ROOT?=$(realpath ../boringtun)
CPPFLAGS+=-I$(BORINGTUN_ROOT)/boringtun/src
LDFLAGS+=-L$(BORINGTUN_ROOT)/target/release
LDLIBS+=-l:libboringtun.a

# mkdir build; cd build; cmake ..; make
FMT_ROOT?=$(realpath ../fmt)
CPPFLAGS+=-I$(FMT_ROOT)/include
LDFLAGS+=-L$(FMT_ROOT)/build
LDLIBS+=-lfmt

# mkdir -p out/release; cd out/release; cmake ../..; make
MIMALLOC_ROOT?=$(realpath ../mimalloc)
CPPFLAGS+=-I$(MIMALLOC_ROOT)/include
LDFLAGS+=-L$(MIMALLOC_ROOT)/out/release
LDLIBS+=-l:libmimalloc.a

USE_MIMALLOC?=1
USE_MIMALLOC_DYNAMIC?=0
OBJ_MIMALLOC=
ifneq ($(SANITIZE), 1)
ifeq ($(USE_MIMALLOC), 1)
	ifeq ($(USE_MIMALLOC_DYNAMIC), 1)
	OBJ_MIMALLOC=util/mimalloc_hijack.o
	else
	OBJ_MIMALLOC=$(MIMALLOC_ROOT)/out/release/mimalloc.o
	endif
endif
endif

XXHASH_ROOT?=$(realpath ../xxHash)
CPPFLAGS+=-I$(XXHASH_ROOT) -DXXH_INLINE_ALL

URCU_ROOT?=$(realpath ../userspace-rcu)
CPPFLAGS+=-I$(URCU_ROOT)/include -D_LGPL_SOURCE
LDFLAGS+=-L$(URCU_ROOT)/src
LDLIBS+=-l:liburcu-qsbr.a -l:liburcu-cds.a

# mkdir build; cd build; cmake .. -DLIBTINS_BUILD_SHARED=0 -DLIBTINS_ENABLE_CXX11=1; make
TINS_ROOT?=$(realpath ../libtins)
TINS_CPPFLAGS+=-I$(TINS_ROOT)/include
TINS_LDFLAGS+=-L$(TINS_ROOT)/build/lib
TINS_LDLIBS+=-ltins

# mkdir build; cd build; cmake ..; make
CATCH_ROOT?=$(realpath ../Catch2)
CATCH_CPPFLAGS+=-I$(CATCH_ROOT)/src -I$(CATCH_ROOT)/build/generated-includes
CATCH_LDFLAGS+=-L$(CATCH_ROOT)/build/src
CATCH_LDLIBS+=-lCatch2Main -lCatch2

# NOTE: customize processor features as desired
# make ENABLE_AVX=1 MARCH=native; make check
FASTCSUM_ROOT?=$(realpath ../fastcsum)
CPPFLAGS+=-I$(FASTCSUM_ROOT)/include
LDFLAGS+=-L$(FASTCSUM_ROOT)
LDLIBS+=-lfastcsum

ifeq ($(DEBUG), 1)
	CPPFLAGS+=-DDEBUG=1
	CFLAGS+=-O0 -g3
	CXXFLAGS+=-O0 -g3
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
	wireglider \

TESTS=\
	tests/test-checksum \
	tests/test-offload \
	tests/test-endian \
	tests/test-flowkey \
	tests/test-flowkey-ref \
	tests/test-ancillary \
	tests/test-sizes \

$(TESTS): CPPFLAGS+=$(CATCH_CPPFLAGS) $(TINS_CPPFLAGS)
$(TESTS): CFLAGS+=-Wno-unused -Wno-shadow
$(TESTS): CXXFLAGS+=-Wno-unused -Wno-shadow
$(TESTS): LDFLAGS+=$(CATCH_LDFLAGS) $(TINS_LDFLAGS)
$(TESTS): LDLIBS=-ltdutil -lfmt -lfastcsum $(CATCH_LDLIBS) $(TINS_LDLIBS)

OBJECTS=\
	worker.o \
	worker/decap.o \
	worker/decap_ref.o \
	worker/encap.o \
	worker/offload.o \
	worker/flowkey.o \
	worker/flowkey_ref.o \
	worker/send.o \
	worker/write.o \
	control.o \
	timer.o \
	netutil.o \
	prefix.o \
	checksum.o \
	liblinux/maple_tree.o \
	liblinux/kernel_compat.o \

DEPS=$(patsubst %.o,%.d,$(OBJECTS))

all: $(TARGETS) $(TESTS)

tests: $(TESTS)

$(TARGETS): $(OBJECTS)

$(TARGETS): %: %.cpp $(OBJ_MIMALLOC)
	$(LINK.cpp) $(OBJ_MIMALLOC) $< $(filter-out $(OBJ_MIMALLOC),$(filter %.o,$^)) $(LOADLIBES) $(LDLIBS) -o $@

$(TESTS): %: %.cpp
	$(LINK.cpp) $< $(filter %.o,$^) $(LOADLIBES) $(LDLIBS) -o $@

tests/test-checksum: checksum.o

tests/test-offload: worker/offload.o checksum.o

tests/test-flowkey: worker/flowkey.o checksum.o

tests/test-flowkey-ref: worker/flowkey_ref.o checksum.o

liblinux/xarray.o: CXXFLAGS+=-Wno-volatile -Wno-unused-parameter -Wno-missing-field-initializers -Wno-sign-compare -Wno-narrowing

liblinux/maple_tree.o: CXXFLAGS+=-Wno-volatile -Wno-unused-parameter -Wno-missing-field-initializers -Wno-sign-compare -Wno-narrowing

run: wireglider
	sudo ./$< -a 0.0.0.0:51820 -A 10.77.44.1/24 -j 1 -k CFuyy4SGWowjnqtGOlq3ywHObkOU4EXvD/UFErXcqlM=

debug: wireglider
	sudo gdb -ex "start -a 0.0.0.0:51820 -A 10.77.44.1/24 -k CFuyy4SGWowjnqtGOlq3ywHObkOU4EXvD/UFErXcqlM=" ./$<

check: tests
	@if (for test in $(TESTS); do echo $$test; $$test || exit; done); then \
		echo "All tests succeeded"; \
	else \
		echo "Some tests failed"; \
		false; \
	fi

clean:
	$(RM) $(TARGETS) $(TESTS)
	$(RM) $(OBJECTS)
	$(RM) $(DEPS)
	find . -name '*.[od]' -print -delete

.PHONY: $(TESTS_RUN) run debug check clean

-include $(DEPS) $(wildcard tests/*.d)
