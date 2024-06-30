#!/usr/bin/env bash

set -ex

function compile() {
    src=$1
    dst=$2
    ${CC} ${CFLAGS} -O3 -c -nostdlib  \
      -fcf-protection=none \
      -fno-stack-protector \
      -ffunction-sections \
      -fno-asynchronous-unwind-tables \
      -o "${dst}.o" "${src}"
    ${LD} -T link.ld -o "${dst}.elf" "${dst}.o"
    ${OBJCOPY} -O binary "${dst}.elf" "${dst}"
}

rm -rf ./*.o ./*.bin ./*.elf ./loader.x86 ./loader.arm64 ./loader.arm32

(
  export CC=clang
  export LD=ld
  export OBJCOPY=objcopy
  ${CC} -O0 -g -o loader.x86 loader.c
#  compile hello_world.c hello_world.x86.bin
  compile unikernel_pid1.c unikernel_pid1.x86.bin
)


(
  export CC="clang -target aarch64-linux-gnu"
  export LD=aarch64-linux-gnu-ld
  export OBJCOPY=aarch64-linux-gnu-objcopy
  export CFLAGS="-mcmodel=tiny" # to use addr instead of addrp
  ${CC} -O0 -g -o loader.arm64 loader.c
#  compile hello_world.c hello_world.arm64.bin
  compile unikernel_pid0_stage0.c unikernel_pid0_stage0.arm64.bin
)

  (
    export CC="clang -target arm-linux-gnueabihf"
    export LD=arm-linux-gnueabihf-ld
    export OBJCOPY=arm-linux-gnueabihf-objcopy
#    export CFLAGS="-mcmodel=tiny" # to use addr instead of addrp
#    ${CC} -O0 -g -o loader.arm32 loader.c
#    compile hello_world.c hello_world.arm32.bin
    compile unikernel_pid0_stage1.c unikernel_pid0_stage1.arm32.bin
  )