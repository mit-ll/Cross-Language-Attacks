DIR=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))

all: rust

dynamic-c:
	clang -fPIC -c -o $(DIR)/src/init/init.o $(DIR)src/init/init.c -fsanitize=cfi -flto -fvisibility=hidden 
	clang -fPIC -shared -o $(DIR)src/init/libinit.so $(DIR)src/init/init.o -fsanitize=cfi -flto -fvisibility=hidden

static-c:
	clang -fPIC -c -o $(DIR)/src/init/init.o $(DIR)src/init/init.c -fsanitize=cfi -flto -fvisibility=hidden 
	ar crs $(DIR)src/init/libinit.a $(DIR)/src/init/init.o 

rust: static-c 
	RUSTFLAGS="-Clinker-plugin-lto -Clinker=clang -Clink-arg=-fuse-ld=lld" cargo build --release

sim: 
	$(DIR)/target/release/cla 

obj: rust 
	objdump -S $(DIR)/target/release/cla > $(DIR)/main.obj
	
clean:
	rm -rf target
	rm -f $(DIR)/src/init/libinit.a
	rm -f $(DIR)/src/init/libinit.so
	rm -f $(DIR)/src/init/init.o
	rm -f $(DIR)/main.obj
