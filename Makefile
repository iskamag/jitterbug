# mrx-al09-root -- build rules for the device-side binaries.
#
#   make su        the permission su stack (sud, su, sumgr)
#   make channel    pcwrite2 + the libbase hook payload
#   make exploit    mali_boot (CVE-2022-38181)
#   make test       host tests for the su subsystem
#   make all
#
# A cross toolchain is needed for the device binaries.  Point at one with
# NDK=<path> (Android NDK, preferred) or MUSL=<path> (aarch64 musl cross gcc);
# the su stack is built with whichever is given, the exploit needs the NDK
# (it links against Android's liblog/bionic headers).

NDK      ?=
MUSL     ?=
SU_DIR   ?= /data/local/tmp

NDK_CC   := $(firstword $(wildcard $(NDK)/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android30-clang))
MUSL_CC  := $(firstword $(wildcard $(MUSL)/bin/aarch64-linux-musl-gcc))
CL       := $(if $(NDK_CC),$(NDK_CC),clang)
SU_CC    := $(if $(MUSL_CC),$(MUSL_CC),$(if $(NDK_CC),$(NDK_CC),cc))

.PHONY: all su channel exploit test clean

all: su channel exploit

su:
	CC="$(SU_CC)" SU_DIR="$(SU_DIR)" ./su/build.sh

channel: channel/pcwrite2 channel/hook_payload.bin channel/hook_branch.bin

channel/pcwrite2: channel/pcwrite2.c
	"$(CL)" -O2 -static -o $@ $<

# the hook payload is built per-library by channel/build_libhook.sh at run
# time (it needs the target's offsets), so there is nothing to prebuild here;
# the rule exists to make the dependency explicit.
channel/hook_payload.bin channel/hook_branch.bin:
	@echo "hook blobs are produced by channel/build_libhook.sh at bring-up"

exploit: exploit/mali_boot

exploit/mali_boot: exploit/mali_boot.c exploit/mali_shrinker_p7.c \
                   exploit/mb_repair.c exploit/mali_diag.c \
                   exploit/mali.h exploit/mali_base_jm_kernel.h \
                   exploit/midgard.h exploit/hw_lsm_heads.h
	cd exploit && "$(CL)" -DSHELL -O2 -pthread -Dmain=p7_legacy_main -I. \
	    mali_boot.c -o mali_boot

test:
	./su/tests/run.sh

clean:
	rm -f su/su su/sud su/sumgr
	rm -f channel/pcwrite2
	rm -f exploit/mali_boot
