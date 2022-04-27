DIR=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))

all: go

dynamic-c:
	#clang -fPIC -c -o $(DIR)/src/init/init.o $(DIR)src/init/init.c -fsanitize=cfi -flto -fvisibility=hidden 
	#clang -fPIC -shared -o $(DIR)src/init/libinit.so $(DIR)src/init/init.o -fsanitize=cfi -flto -fvisibility=hidden
	clang -fPIC -c -o $(DIR)/src/init/init.o $(DIR)src/init/init.c 
	clang -fPIC -shared -o $(DIR)src/init/libinit.so $(DIR)src/init/init.o 

static-c:
	clang -fPIC -c -o $(DIR)/src/init/init.o $(DIR)src/init/init.c -fsanitize=cfi -flto -fvisibility=hidden 
	ar crs $(DIR)src/init/libinit.a $(DIR)/src/init/init.o 

go: dynamic-c 
	gofmt -e -s -w .
	CGO_CFLAGS="-flto -ffat-lto-objects" go build $(DIR)/src/main.go

sim: 
	LD_LIBRARY_PATH=$(DIR)/src/init/ $(DIR)/main 

obj: go 
	objdump -S $(DIR)/main > $(DIR)/main.obj
	
clean:
	rm -rf $(DIR)/main
	rm -f $(DIR)/src/init/libinit.a
	rm -f $(DIR)/src/init/libinit.so
	rm -f $(DIR)/src/init/init.o
	rm -f $(DIR)/main.obj
