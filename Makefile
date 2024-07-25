# echo datagram | sudo tee /sys/class/net/ibp8s0/mode

# sudo ./wireguard wg0; sudo wg set wg0 listen-port 51820 private-key ~/wg/cumulus.key peer XXmnRm3crIM5cU92d1GA7l5sKzU+wosKfeWAYq1edCY= endpoint 10.88.77.3:51820 allowed-ips 10.77.44.2/32; sudo ip ad add 10.77.44.1/24 dev wg0; sudo ip link set wg0 up
# sudo ./wireguard wg0; sudo wg set wg0 listen-port 51820 private-key ~/wg/stratus.key peer YDUwiJvcaGhsC29P6RfDj0Rf0zOXs6Y99kC7NGJfmT0= endpoint 10.88.77.2:51820 allowed-ips 10.77.44.1/32; sudo ip ad add 10.77.44.2/24 dev wg0; sudo ip link set wg0 up

# sudo tcpdump -w wireglider.pcap port 51820
# sudo tcpdump -i wg0 -w tun.pcap

# wg$ sudo ../copy-nginx.sh
# wget -O/dev/null 10.77.44.1/dev/shm/nginx/vm-cumulus.qcow2
# wget -O/dev/null 10.77.44.2/dev/shm/nginx/vm-cumulus.qcow2

# To summarize the various issues:
# - bandwidth starvation of decap path in bidir mode - also happens with boringtun
#   protocol impl issue within boringtun?
#   or something missing in both impls that wireguard-go has?
# - recvmmsg() is slow AF - conversion to io_uring?
# - crypto scalability - is ring crypto fast enough? Workqueues with work stealing?
# - looping server recv until EAGAIN significantly slows down recv bandwidth compared to one-shot recv
#   where does the issue come from? recv() slowness? or something else?
# - need to implement core affinity system eventually
# - about the sendmmsg/recvmmsg patch...

CPPFLAGS+=-D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -MMD -MP
CPPFLAGS+=-Iinclude -Iinclude/util -Iinclude/netio -Iinclude/proto
CFLAGS+=-Wall -Wextra -Wformat=2 -Werror=shadow -Werror=return-type -std=c11 -fwrapv
CXXFLAGS+=-Wall -Wextra -Wformat=2 -Werror=shadow -Werror=return-type -Wold-style-cast -std=c++20 -fwrapv

USE_CLANG?=0
ifeq ($(USE_CLANG),1)
CC=clang
CXX=clang++
else
#CXXFLAGS+=-fconcepts-diagnostics-depth=2
endif

CPPFLAGS+=-pthread
LDLIBS+=-pthread

# NOTE: customize kernel header include paths if needed
#CPPFLAGS+=-isystem /lib/modules/$(shell uname -r)/build/usr/include

# NOTE: customize processor features as desired
CFLAGS+=-march=native
CXXFLAGS+=-march=native

# make
TDUTIL_ROOT?=$(realpath ../tdutil)
CPPFLAGS+=-isystem $(TDUTIL_ROOT)/include
LDFLAGS+=-L$(TDUTIL_ROOT)
LDLIBS+=-ltdutil

# ./configure; make
LIBURING_ROOT?=$(realpath ../liburing)
CPPFLAGS+=-isystem $(LIBURING_ROOT)/src/include
LDFLAGS+=-L$(LIBURING_ROOT)/src
LDLIBS+=-l:liburing.a

# ./b2 variant=release link=static runtime-link=shared stage
BOOST_ROOT?=$(realpath ../boost_1_85_0)
CPPFLAGS+=-isystem $(BOOST_ROOT) -DBOOST_ENDIAN_NO_CTORS
LDFLAGS+=-L$(BOOST_ROOT)/stage/lib
LDLIBS+=

# requires libcxxopts-dev
CPPFLAGS+=$(shell pkg-config --cflags cxxopts)

# mkdir build; cd build; cmake ..; make
FMT_ROOT?=$(realpath ../fmt)
CPPFLAGS+=-isystem $(FMT_ROOT)/include
LDFLAGS+=-L$(FMT_ROOT)/build
LDLIBS+=-lfmt

# mkdir -p out/release; cd out/release; cmake ../..; make
MIMALLOC_ROOT?=$(realpath ../mimalloc)
CPPFLAGS+=-isystem $(MIMALLOC_ROOT)/include
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

# requires libxxhash-dev
CPPFLAGS+=-DXXH_INLINE_ALL $(shell pkg-config --cflags libxxhash)

# NOTE: customize processor features as desired
# mkdir build; cd build; cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake -DENABLE_AVX=true -DARCH=native; make
FASTCSUM_ROOT?=$(realpath ../fastcsum)
CPPFLAGS+=-isystem $(FASTCSUM_ROOT)/include
LDFLAGS+=-L$(FASTCSUM_ROOT)
LDLIBS+=-lfastcsum

# requires liburcu-dev
CPPFLAGS+=-D_LGPL_SOURCE $(shell pkg-config --cflags liburcu-qsbr liburcu-cds)
LDLIBS+=$(shell pkg-config --libs liburcu-qsbr liburcu-cds)

# requires libsodium-dev
CPPFLAGS+=$(shell pkg-config --cflags libsodium)
LDLIBS+=$(shell pkg-config --libs libsodium)

NOISEC_ROOT?=$(realpath ../noise-c)
# ./autogen.sh; ./configure --with-libsodium; make
CPPFLAGS+=-isystem $(NOISEC_ROOT)/include
LDFLAGS+=-L$(NOISEC_ROOT)/src/protocol

# requires libtins-dev
TINS_CPPFLAGS+=$(shell pkg-config --cflags libtins)
TINS_LDLIBS+=$(shell pkg-config --libs libtins)

# mkdir build; cd build; cmake ..; make
CATCH_ROOT?=$(realpath ../Catch2)
CATCH_CPPFLAGS+=-isystem $(CATCH_ROOT)/src -isystem $(CATCH_ROOT)/build/generated-includes
CATCH_LDFLAGS+=-L$(CATCH_ROOT)/build/src
CATCH_LDLIBS+=-lCatch2Main -lCatch2

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
		CFLAGS+=-flto=auto -fuse-linker-plugin
		CXXFLAGS+=-flto=auto -fuse-linker-plugin
		LDFLAGS+=-flto=auto -fuse-linker-plugin
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
	tests/test-flowkey-own \
	tests/test-flowkey-ref \
	tests/test-ancillary \
	tests/test-sizes \
	tests/test-replay \

TOOLS=\
	nettool \

$(TESTS): CPPFLAGS+=$(CATCH_CPPFLAGS) $(TINS_CPPFLAGS)
$(TESTS): CFLAGS+=-Wno-unused -Wno-shadow
$(TESTS): CXXFLAGS+=-Wno-unused -Wno-shadow
$(TESTS): LDFLAGS+=$(CATCH_LDFLAGS) $(TINS_LDFLAGS)
$(TESTS): LDLIBS=-ltdutil -lfmt -lfastcsum $(CATCH_LDLIBS) $(TINS_LDLIBS)

OBJECTS=\
	worker.o \
	worker/decap.o \
	worker/decap_own.o \
	worker/decap_ref.o \
	worker/encap.o \
	worker/offload.o \
	worker/flowkey_own.o \
	worker/flowkey_ref.o \
	worker/send.o \
	worker/write_own.o \
	worker/write_ref.o \
	control.o \
	timer.o \
	netutil.o \
	prefix.o \
	checksum.o \
	liblinux/maple_tree.o \
	liblinux/kernel_compat.o \

DEPS=$(patsubst %.o,%.d,$(OBJECTS))
SOURCES=$(patsubst %,%.cpp,$(TARGETS) $(TESTS)) $(patsubst %.o,%.cpp,$(filter-out liblinux/%,$(OBJECTS)))

all: $(TARGETS) $(TESTS) $(TOOLS)

tests: $(TESTS)

tools: $(TOOLS)

$(TARGETS): $(OBJECTS)

$(TARGETS): %: %.cpp $(OBJ_MIMALLOC)
	$(LINK.cpp) $(OBJ_MIMALLOC) $< $(filter-out $(OBJ_MIMALLOC),$(filter %.o,$^)) $(LOADLIBES) $(LDLIBS) -o $@

$(TESTS): %: %.cpp
	$(LINK.cpp) $< $(filter %.o,$^) $(LOADLIBES) $(LDLIBS) -o $@

$(TESTS): CXXFLAGS+=-Wno-unused-parameter -Wno-deprecated-declarations

tests/test-checksum: checksum.o

tests/test-offload: worker/offload.o checksum.o

tests/test-flowkey-own: worker/flowkey_own.o checksum.o

tests/test-flowkey-ref: worker/flowkey_ref.o checksum.o

nettool: LDLIBS=-lfmt
nettool: netutil.o

liblinux/maple_tree.o liblinux/kernel_compat.o: CXXFLAGS+=-Wno-unused-parameter -Wno-missing-field-initializers -Wno-sign-compare -Wno-narrowing -Wno-old-style-cast

ifeq ($(USE_CLANG),1)
liblinux/maple_tree.o liblinux/kernel_compat.o: CXXFLAGS+=-Wno-deprecated-volatile -Wno-unused-function -Wno-c99-designator
else
liblinux/maple_tree.o liblinux/kernel_compat.o: CXXFLAGS+=-Wno-volatile
endif

run: wireglider
	sudo ./run.sh

debug: wireglider
	sudo gdb -ex "start -a 0.0.0.0:51820 -A 10.77.44.2/24 -k CFuyy4SGWowjnqtGOlq3ywHObkOU4EXvD/UFErXcqlM= -j 8" ./$<

check: tests
	@if (for test in $(TESTS); do echo $$test; $$test || exit; done); then \
		echo "All tests succeeded"; \
	else \
		echo "Some tests failed"; \
		false; \
	fi

cloc:
	cloc --config .clocconfig .

tidy:
	clang-tidy $(SOURCES) -- $(CPPFLAGS) $(CXXFLAGS)

format:
	clang-format --dry-run $(SOURCES)
	@echo "use make format-commit to save changes"

format-commit:
	clang-format -i $(SOURCES)

clean:
	$(RM) $(TARGETS) $(TESTS)
	$(RM) $(OBJECTS)
	$(RM) $(DEPS)
	find . -name '*.[od]' -print -delete

.PHONY: $(TESTS_RUN) run debug check cloc tidy clean

-include $(DEPS) $(wildcard tests/*.d)
