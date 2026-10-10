CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wno-missing-field-initializers
# flags that give simple, linkable, debuggable objects (no PIE, no libc assumptions)
CFLAGS_OBJ = -c -g -O0 -ffreestanding -fno-pic -fno-pie -fno-stack-protector \
             -fno-asynchronous-unwind-tables -fcf-protection=none $(EXTRA_CFLAGS)

B = build
OBJS = $(B)/start.o $(B)/main.o $(B)/mathutil.o $(B)/syscalls.o

all: mylink mydbg demo

mylink: src/mylink.cpp src/elfreader.h
	$(CXX) $(CXXFLAGS) -o $@ $<
mydbg: src/mydbg.cpp src/elfreader.h
	$(CXX) $(CXXFLAGS) -o $@ $<

$(B):
	mkdir -p $(B)
$(B)/start.o: examples/start.S | $(B)
	gcc -c -g $< -o $@
$(B)/%.o: examples/%.c | $(B)
	gcc $(CFLAGS_OBJ) $< -o $@

demo: mylink $(OBJS)
	./mylink $(OBJS) -o $(B)/demo
	@echo "built $(B)/demo  (run: ./$(B)/demo ; debug: ./mydbg $(B)/demo)"

# same objects linked by GNU ld, for comparison
demo-ld: $(OBJS)
	ld -static -nostdlib -no-pie -e _start $(OBJS) -o $(B)/demo_ld

test: all demo-ld
	bash tests/run_tests.sh

clean:
	rm -rf $(B) mylink mydbg
.PHONY: all demo demo-ld test clean
