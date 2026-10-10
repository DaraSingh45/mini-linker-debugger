#!/usr/bin/env bash
# End-to-end checks: mylink vs GNU ld, DWARF line table vs objdump, debugger session.
set -u
cd "$(dirname "$0")/.."
B=build; PASS=0; FAIL=0
ok()   { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
check(){ if eval "$2" >/dev/null 2>&1; then ok "$1"; else bad "$1"; fi; }

CF="-c -g -O0 -ffreestanding -fno-pic -fno-pie -fno-stack-protector -fno-asynchronous-unwind-tables -fcf-protection=none"
OBJS="$B/start.o $B/main.o $B/mathutil.o $B/syscalls.o"
mkdir -p $B/t

echo "== linker =="
./mylink $OBJS -o $B/t/mine
ld -static -nostdlib -no-pie -e _start $OBJS -o $B/t/ref
$B/t/mine > $B/t/mine.out; echo $? > $B/t/mine.rc
$B/t/ref  > $B/t/ref.out;  echo $? > $B/t/ref.rc
check "program runs and exits 0"                    "[ \$(cat $B/t/mine.rc) = 0 ]"
check "same stdout and exit code as GNU ld output"  "cmp $B/t/mine.out $B/t/ref.out && cmp $B/t/mine.rc $B/t/ref.rc"
norm(){ objdump -d --no-show-raw-insn "$1" | sed -E 's/^ *[0-9a-f]+:\t?//; s/^[0-9a-f]+ </</; s/0x[0-9a-f]+/N/g; s/\b[0-9a-f]{6,}\b/ADDR/g' | grep -v 'file format'; }
check "disassembly matches ld (addresses normalised)" "diff <(norm $B/t/mine) <(norm $B/t/ref)"
sy(){ nm "$1" | awk '{print $2,$3}' | sort; }
check "same symbol names/types as ld (nm)"          "diff <(sy $B/t/mine) <(sy $B/t/ref)"
check "readelf accepts the file (no warnings)"      "[ -z \"\$(readelf -a $B/t/mine 2>&1 >/dev/null)\" ]"
# relocated absolute pointers in .data (R_X86_64_64) point at the right functions
check "R_X86_64_64: operations[] -> <add>, <multiply>" "printf 'break main.c:23\nrun\nprint operations\nquit\n' | ./mydbg $B/t/mine | grep -q '<add>.*<multiply>'"
gcc $CF examples/undefined_demo.c -o $B/t/undef.o; gcc $CF examples/dup_demo.c -o $B/t/dup.o
check "undefined symbol is an error"  "./mylink $B/start.o $B/t/undef.o -o $B/t/x 2>&1 | grep -q 'undefined reference to .missing_function.'"
check "duplicate symbol is an error"  "./mylink $OBJS $B/t/dup.o -o $B/t/x 2>&1 | grep -q \"duplicate symbol 'add'\""
check "no output file on error"       "[ ! -e $B/t/x ]"
ar rcs $B/t/libm.a $B/mathutil.o $B/syscalls.o
./mylink $B/start.o $B/main.o $B/t/libm.a -o $B/t/ar_exe
check "archive (.a) link works"       "$B/t/ar_exe | cmp - $B/t/ref.out"
./mylink --section-order=data,rodata,text $OBJS -o $B/t/ord
check "--section-order=data,rodata,text works" "$B/t/ord | cmp - $B/t/ref.out"
./mylink --base=0x10000000 $OBJS -o $B/t/base
check "--base=0x10000000 works"       "$B/t/base | cmp - $B/t/ref.out"

echo "== DWARF line table =="
dumpmine(){ ./mydbg "$1" <<< "lines" | awk '$1 ~ /^0x/ && $2 != "-" {printf "%s %s\n",$1,$2}' | sed -E 's/0x0*/0x/' | sort -u; }
dumpobj(){ objdump --dwarf=decodedline "$1" | awk '$3 ~ /^0x/ && $2 != "-" {printf "%s %s\n",$3,$2}' | sed -E 's/0x0*/0x/' | sort -u; }
check "mydbg line table == objdump --dwarf=decodedline" "diff <(dumpmine $B/t/mine) <(dumpobj $B/t/mine)"

echo "== debugger =="
cat > $B/t/cmds <<'CMDS'
break main.c:23
break factorial
run
print a
print/x b
print global_counter
continue
args
bt
quit
CMDS
./mydbg $B/t/mine < $B/t/cmds > $B/t/dbg.out 2>&1
check "breakpoint by file:line hit"           "grep -q 'Breakpoint 1, main () at main.c:23' $B/t/dbg.out"
check "local int printed by name"             "grep -q '^6\$' $B/t/dbg.out"
check "print/x works"                         "grep -q '^0x7\$' $B/t/dbg.out"
check "global variable printed"               "grep -q '^100\$' $B/t/dbg.out"
check "breakpoint by function name"           "grep -q 'Breakpoint 2, factorial () at mathutil.c:23' $B/t/dbg.out"
check "function argument printed"             "grep -q '^n = 5\$' $B/t/dbg.out"
check "backtrace shows caller"                "grep -q '#1  0x[0-9a-f]* in main () at main.c:25' $B/t/dbg.out"
printf 'break mathutil.c:16\nrun\nstep\nstep\nquit\n' | ./mydbg $B/t/mine > $B/t/step.out 2>&1
check "step enters add()"                     "grep -q 'add () at mathutil.c:7' $B/t/step.out"
printf 'break mathutil.c:16\nrun\nnext\nquit\n' | ./mydbg $B/t/mine > $B/t/next.out 2>&1
check "next steps over add()"                 "grep -q '^15' $B/t/next.out && ! grep -q 'add () at' $B/t/next.out"
check "debugger also reads the ld-built exe"  "printf 'break main.c:23\nrun\nprint a\nquit\n' | ./mydbg $B/t/ref | grep -q '^6\$'"

echo "== DWARF 4 objects =="
mkdir -p $B/d4
for f in main mathutil syscalls; do gcc $CF -gdwarf-4 examples/$f.c -o $B/d4/$f.o; done
gcc -c -g -gdwarf-4 examples/start.S -o $B/d4/start.o
./mylink $B/d4/start.o $B/d4/main.o $B/d4/mathutil.o $B/d4/syscalls.o -o $B/d4/demo
check "DWARF-4 build runs"                    "$B/d4/demo | cmp - $B/t/ref.out"
check "DWARF-4 break + print locals"          "printf 'break main.c:23\nrun\nlocals\nquit\n' | ./mydbg -d examples $B/d4/demo | grep -q 'a = 6'"

echo; echo "passed: $PASS  failed: $FAIL"; [ $FAIL = 0 ]
