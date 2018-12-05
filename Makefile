
SRCS := $(shell find cmd hash record scanner store -name '*.go')
BINS := binprint snapcat

# Default target is the cli
all: $(BINS)

LIBGIT2 := vendor/gopkg.in/libgit2/git2go.v27/vendor/libgit2
LIBGIT2PC := $(LIBGIT2)/build/libgit2.pc

# some static analysis tools require setting this ourselves because they don't
# understand how to use build tags
PKG_CONFIG_PATH := $(dir $(LIBGIT2PC))

binprint: $(SRCS) $(LIBGIT2PC)
	go build -o $@ --tags "static" ./cmd/binprint
# this won't work on macos because it a static version of crt0 doesn't actually exist
#	go build -ldflags '-v -extldflags "-static"' -o $@ --tags "static" ./cli

snapcat: cmd/snapcat/main.go
	go build -o $@ ./$(^D)

unused: $(LIBGIT2PC)
	PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) unused ./...

test:
	go test --tags "static" -v ./...

$(LIBGIT2)/CMakeLists.txt:
	git submodule update --init $(@D)

$(LIBGIT2PC): $(LIBGIT2)/CMakeLists.txt
	mkdir -p $(@D) $(LIBGIT2)/install/lib
	cd $(@D) && \
		cmake -DTHREADSAFE=ON \
			-DBUILD_CLAR=OFF \
			-DUSE_SSH=OFF \
			-DUSE_HTTPS=OFF \
			-DCURL=OFF \
			-DBUILD_SHARED_LIBS=OFF \
			-DCMAKE_C_FLAGS=-fPIC \
			-DCMAKE_INSTALL_PREFIX=../install \
			-DCMAKE_BUILD_TYPE="MinSizeRel" \
		.. && \
	  cmake --build . --target install

clean:
	rm -f $(BINS) $(LIBGIT2PC)

.randomblob:
	dd if=/dev/urandom of=$@ bs=512k count=1000

validate-hashes: binprint .randomblob
	time md5sum .randomblob
	time ./binprint hash md5 .randomblob
	time shasum .randomblob
	time ./binprint hash sha1 .randomblob
	time shasum -a 256 .randomblob
	time ./binprint hash sha256 .randomblob
	time shasum -a 384 .randomblob
	time ./binprint hash sha384 .randomblob
	time shasum -a 512 .randomblob
	time ./binprint hash sha512 .randomblob
	time git hash-object .randomblob
	time ./binprint hash git .randomblob
	time ./binprint hash hwy64 .randomblob
	time ./binprint hash hwy128 .randomblob
	time ./binprint hash hwy256 .randomblob
	time ./binprint hash all .randomblob
