# Mini Static Linker + Source-Level Debugger (x86-64 Linux)

Two connected tools written in C++17 with **no dependencies beyond the standard library and Linux headers**:

| Tool | What it does |
|------|--------------|
| `mylink` | Links ELF relocatable `.o` files (and `.a` archives) from `gcc -c` into a runnable static executable |
| `mydbg`  | Runs that executable under `ptrace`; breakpoints by `file.c:line`, stepping, registers, prints variables by name |

```
 main.c  mathutil.c  syscalls.c  start.S
    │  gcc -c -g
    ▼
 main.o  mathutil.o  syscalls.o  start.o ──►  mylink  ──►  demo (ELF executable + DWARF)
                                                              │
                                                              ▼
                                                            mydbg  (ptrace + .debug_line + .debug_info)
```

---------------------------------------------------------------------

## 1. Requirements

### Operating system / hardware
* **x86-64 Linux** (Ubuntu 22.04 / 24.04 recommended). Intel/AMD CPU.
* Windows → use **WSL2** (Ubuntu). `ptrace` works in WSL2 (not in WSL1).
* macOS / Apple-silicon / ARM Linux will **not** work (different ELF machine type, no Linux `ptrace`).
* Docker: add `--cap-add=SYS_PTRACE --security-opt seccomp=unconfined`, otherwise `ptrace` is blocked.
* VM or bare metal are both fine.

### Packages
```bash
sudo apt update
sudo apt install build-essential binutils make
```
This gives you everything used:

| Tool | Package | Needed for |
|------|---------|-----------|
| `g++` (C++17, GCC ≥ 9) | build-essential | building `mylink` / `mydbg` |
| `gcc` | build-essential | producing the `.o` files (`gcc -c`) |
| `make` | make | the Makefile |
| `ld`, `ar`, `nm`, `objdump`, `readelf` | binutils | **verification** (comparing against the real linker) and building `.a` archives |
| `gdb` *(optional)* | gdb | cross-checking your debugger against the real one |
| `git` *(optional)* | git | putting the project on GitHub (the application asks for a GitHub link) |

Tested with: Ubuntu 24.04, GCC 13.3, binutils 2.42, kernel 6.x. Default GCC output (DWARF 5) and `-gdwarf-4` are both supported.

### Linux settings (only if the debugger can't start)
`cat /proc/sys/kernel/yama/ptrace_scope` – value `0` or `1` is fine. (`mydbg` launches the program itself,
so even `1` works; only `3` would block it.)

---------------------------------------------------------------------

## 2. Build everything (one command)

```bash
cd mini-toolchain
make
```
This
1. compiles `mylink` and `mydbg`,
2. compiles the example C program into `.o` files with the required flags,
3. links them with **your** linker into `build/demo`.

Run the result:
```bash
./build/demo
echo "exit code: $?"
```
Expected output
```
== mini-linker demo ==
Hello from a program linked by mylink!
sum = 13
product = 42
factorial(5) = 120
global_counter = 142
add() calls = 8
exit code: 0
```

### Why those compiler flags?
`gcc -c -g -O0 -ffreestanding -fno-pic -fno-pie -fno-stack-protector -fno-asynchronous-unwind-tables -fcf-protection=none`

| Flag | Reason |
|------|--------|
| `-c` | produce a relocatable `.o` |
| `-g -O0` | DWARF debug info; `-O0` keeps variables in stack slots so the debugger can find them |
| `-fno-pic -fno-pie` | absolute addressing, only the simple relocations (no GOT/PLT) |
| `-ffreestanding` | no libc assumptions – the program talks to the kernel with raw `syscall` |
| `-fno-stack-protector` | avoids a reference to `__stack_chk_fail` (libc) |
| `-fno-asynchronous-unwind-tables`, `-fcf-protection=none` | no `.eh_frame` / CET notes to deal with |

---------------------------------------------------------------------

## 3. Using the linker step by step

### 3.1 Compile your sources to objects
```bash
mkdir -p build && cd build
CF="-c -g -O0 -ffreestanding -fno-pic -fno-pie -fno-stack-protector -fno-asynchronous-unwind-tables -fcf-protection=none"
gcc $CF ../examples/main.c     -o main.o
gcc $CF ../examples/mathutil.c -o mathutil.o
gcc $CF ../examples/syscalls.c -o syscalls.o
gcc -c -g ../examples/start.S  -o start.o        # hand-written _start
```

### 3.2 Link
```bash
../mylink start.o main.o mathutil.o syscalls.o -o demo
./demo; echo $?
```

### 3.3 Options
| Option | Meaning |
|--------|---------|
| `-o FILE` | output file (default `a.out`) |
| `-e SYMBOL` | entry symbol (default `_start`) |
| `--base=0x...` | load address (page aligned, default `0x400000`) |
| `--section-order=text,rodata,data` | order of the three segments in memory, e.g. `data,rodata,text` |
| `--map` | print a link map (sections, which input contributed where, symbol addresses) |
| `-v` | verbose (shows archive members that were pulled in) |
| `file.a` | static archives are accepted anywhere on the command line |

```bash
../mylink --map start.o main.o mathutil.o syscalls.o -o demo           # link map
ar rcs libdemo.a mathutil.o syscalls.o
../mylink -v start.o main.o libdemo.a -o demo_ar                        # archive: only needed members are pulled in
../mylink --section-order=data,rodata,text start.o main.o mathutil.o syscalls.o -o demo_reordered
```

### 3.4 See the error handling
```bash
gcc $CF ../examples/undefined_demo.c -o undef.o
../mylink start.o undef.o -o x
# mylink: error: undef.o: undefined reference to 'missing_function'

gcc $CF ../examples/dup_demo.c -o dup.o
../mylink start.o main.o mathutil.o dup.o syscalls.o -o x
# mylink: error: duplicate symbol 'add': defined in mathutil.o and dup.o
```
No output file is written when errors occur.

### 3.5 Prove it matches the real linker
```bash
ld -static -nostdlib -no-pie -e _start start.o main.o mathutil.o syscalls.o -o demo_ld

./demo > mine.txt;  ./demo_ld > ref.txt;  diff mine.txt ref.txt && echo "same behaviour"

readelf -h -l -S demo            # headers, segments, sections of YOUR output
readelf -r main.o                # the relocations your linker had to apply
objdump -d demo | head -60       # disassembly – calls point at the right functions
objdump -s -j .data demo         # .data holds the relocated function pointers (R_X86_64_64)
nm demo | sort                   # symbol table
diff <(nm demo | awk '{print $2,$3}' | sort) <(nm demo_ld | awk '{print $2,$3}' | sort) && echo "same symbols"
```
`make test` automates these comparisons (25 checks).

---------------------------------------------------------------------

## 4. Using the debugger step by step

```bash
./mydbg build/demo                  # interactive
./mydbg -d examples build/demo      # -d DIR : where to look for source files if paths in DWARF don't resolve
./mydbg build/demo arg1 arg2        # pass arguments to the program
./mydbg build/demo < cmds.txt       # run a script of commands (commands are echoed)
```
It also works on the `ld`-linked binary or any **non-PIE static** binary (`gcc -static -no-pie`). PIE binaries are rejected with a message.

### 4.1 Command reference
| Command | Description |
|---------|-------------|
| `break file.c:12` / `b 12` / `b func` / `b *0x401000` | set breakpoint (`func` stops *after* the prologue so locals are valid) |
| `run` / `r` | start the program |
| `continue` / `c` | resume |
| `next` / `n` | run to next source line, stepping **over** calls |
| `step` / `s` | next source line, stepping **into** functions that have line info |
| `stepi` / `si` | one machine instruction |
| `finish` | run until the current function returns |
| `print x`, `print/x x`, `p &x`, `p $rax` | variables (ints, chars, bool, float/double, pointers, `char*` strings, arrays, structs, enums) and registers |
| `locals` / `args` | all variables / parameters in scope |
| `set var x = 5` | modify a variable in the running program |
| `x/4x $rsp`, `x/s greeting` | examine memory (8-byte words or string) |
| `regs` | dump all registers |
| `bt` | backtrace (frame-pointer chain) |
| `list`, `list 20`, `list mathutil.c:20`, `list main` | show source |
| `info breakpoints`, `delete [N]`, `enable/disable [N]` | manage breakpoints |
| `lines` | dump the decoded line table (compare with `objdump --dwarf=decodedline`) |
| `info functions` | functions found in DWARF |
| `help`, `quit` | |

### 4.2 Walk-through (copy/paste)
Line numbers refer to `examples/main.c` and `examples/mathutil.c`.

```
$ ./mydbg build/demo
(mydbg) break main.c:23
Breakpoint 1 at 0x40015f: file main.c:23
(mydbg) break multiply
Breakpoint 2 at 0x40026b: file mathutil.c:13
(mydbg) run
== mini-linker demo ==
Hello from a program linked by mylink!

Breakpoint 1, main () at main.c:23
23	    sum = operations[0](a, b);
(mydbg) locals
a = 6
b = 7
sum = 0
product = 0
fact = 0
(mydbg) print greeting
(const char*) 0x401018 "Hello from a program linked by mylink!\n"
(mydbg) print operations
{(binop) 0x40023a <add>, (binop) 0x40025d <multiply>}      <- R_X86_64_64 relocations resolved by your linker
(mydbg) print &global_counter
(int*) 0x402000 <global_counter>
(mydbg) next
24	    product = operations[1](a, b);
(mydbg) next

Breakpoint 2, multiply () at mathutil.c:13
13	    int result = 0;
(mydbg) bt
#0  multiply () at mathutil.c:13
#1  0x0000000000400188 in main () at main.c:24
(mydbg) step
15	    for (i = 0; i < b; i++) {
(mydbg) step
16	        result = add(result, a);
(mydbg) step
add () at mathutil.c:7
7	    call_count++;
(mydbg) finish
(mydbg) set var result = 100        # change program state...
(mydbg) continue                    # ...and watch the program's output/exit code change
```
Bug-hunting demo: `break mathutil.c:16`, `run`, `set var result = 100`, `continue` → final output shows `product = 142` and the exit code becomes 1.

### 4.3 Cross-check against the real tools
```bash
./mydbg build/demo <<< "lines" | head                 # your line table
objdump --dwarf=decodedline build/demo | head -30     # reference
gdb -q build/demo                                     # optional: same breakpoints in real gdb
```

---------------------------------------------------------------------

## 5. Project layout
```
mini-toolchain/
├── Makefile                  make | make test | make clean
├── README.md
├── src/
│   ├── elfreader.h           ELF64 file reader shared by both tools
│   ├── mylink.cpp            the linker            (~760 lines)
│   └── mydbg.cpp             the debugger          (~1200 lines)
├── examples/
│   ├── start.S               hand-written _start (no libc)
│   ├── main.c mathutil.c(.h) syscalls.c(.h)     demo program (multi-file, recursion, function pointers, .data/.bss/.rodata)
│   └── undefined_demo.c dup_demo.c              error-handling demos
└── tests/run_tests.sh        25 automated checks vs. ld / objdump / readelf
```

## 6. How it works (for interview explanations)

**Linker**
1. *Parse* each `.o`: section headers, `.symtab`, `.rela.*` tables (`elfreader.h`, `mylink.cpp`).
2. *Symbol resolution*: one global table; strong/weak/COMMON rules; duplicate → error; undefined → error; archive members are extracted iteratively only if they define a still-undefined symbol.
3. *Layout*: every input section is classified by flags (exec → `.text`, read-only → `.rodata`, writable → `.data`, NOBITS → `.bss`), appended with alignment, then three `PT_LOAD` segments are placed on page boundaries (`vaddr = base + file offset`). `.debug_*` sections are merged too (non-allocated, "address 0") so the debugger has DWARF.
4. *Relocation*: for `S` = symbol address, `A` = addend, `P` = place address:
   `R_X86_64_64: S+A` · `R_X86_64_PC32 / PLT32: S+A−P` (a static link needs no PLT, so PLT32 == PC32) · `R_X86_64_32 / 32S: S+A` with range checks · `R_X86_64_PC64`. The same code patches the DWARF sections.
5. *Emit*: ELF header, program headers (+`PT_GNU_STACK`), section headers, `.symtab/.strtab`; linker-defined symbols `_end`, `_edata`, `__bss_start`.

**Debugger**
* `fork` → `PTRACE_TRACEME` → `execv`; `waitpid` for stops.
* Breakpoint = overwrite first byte with `0xCC` (`int3`); on `SIGTRAP` set `rip -= 1`; to resume, restore the byte, single-step, re-insert.
* `.debug_line`: LEB128 state machine (standard + special + extended opcodes; v2–v5 headers) → sorted `(address → file:line)` table used for `break file:line`, `next/step`, and source display.
* `.debug_info` + `.debug_abbrev`: DIE tree → functions (`low_pc/high_pc`), variables (`DW_OP_fbreg` relative to the frame base, `DW_OP_addr` for globals), type DIEs for printing.
* `next` = single-step; if the instruction is a `call`, plant a temporary breakpoint at the return address and continue.

## 7. Known limitations (be upfront about them in the interview)
* Linux x86-64 only, static, non-PIE; no shared libraries, GOT/PLT, TLS, `.init_array`, C++ exceptions.
* Debugger assumes `-O0` frame-pointer code (variables via `DW_OP_fbreg` with CFA = `rbp+16`); optimised code with location lists shows `<optimized out>`.
* No watchpoints, conditional breakpoints, multi-threading, or `.eh_frame`-based unwinding.
* Linker scripts are not supported; `--section-order` is the lightweight alternative.

## 8. Ideas to extend (shows initiative)
* Conditional breakpoints (`break f if x == 3`), `tbreak`, watchpoints with hardware debug registers.
* `R_X86_64_GOTPCRELX` relaxation so `-fPIE` objects link; section garbage collection (`--gc-sections`).
* Parse `.eh_frame` for correct unwinding of optimised code.
* Port the debugger's line-table/DIE parsing to a `--dump-dwarf` tool and fuzz it.
