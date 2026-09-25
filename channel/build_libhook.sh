#!/bin/bash
# Generic cold-function hook builder (offsets are file/vaddr offsets in a
# /system library where .text vaddr == file offset).
#
# usage: build_libhook.sh <libfile> <T_off_hex> <H_off_hex> <T4_off_hex> <pid>
# Outputs: hook_payload.bin (write at H_off), hook_branch.bin (write at T_off)
set -e
LIB="$1"; T="$2"; H="$3"; T4="$4"; PID="$5"
cd "$(dirname "$0")"
T0=$(dd if="$LIB" bs=1 skip=$((T)) count=4 2>/dev/null | od -An -tx4 | tr -d ' \n')
sed -e "s/@PID@/$PID/" -e "s/@T0@/0x$T0/" payload_libhook.S > payload_libhook.gen.S
clang --target=aarch64-linux-android -c payload_libhook.gen.S -o payload_libhook.o
ld.lld -o payload_libhook.elf --image-base=0 --section-start=.text=$H --defsym=T4=$T4 payload_libhook.o
llvm-objcopy -O binary --only-section=.text payload_libhook.elf hook_payload.bin
START=$(llvm-nm payload_libhook.elf | awk '$3=="_start"{print "0x"$1}')
echo "T=$T H=$H T4=$T4 T0_insn=0x$T0 _start=$START payload=$(stat -c%s hook_payload.bin) bytes"
python3 - "$T" "$H" <<'EOF'
import sys, os
t=int(sys.argv[1],16); h=int(sys.argv[2],16)
off=h-t; assert off%4==0, hex(off)
insn=0x14000000|((off>>2)&0x3ffffff)
open('hook_branch.bin','wb').write(insn.to_bytes(4,'little'))
print("branch at 0x%x -> 0x%x insn=%08x payload=%d bytes" % (t,h,insn,os.path.getsize('hook_payload.bin')))
EOF
