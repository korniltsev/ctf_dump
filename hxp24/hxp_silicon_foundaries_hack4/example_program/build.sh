#!/bin/sh
set -ex
nasm -f elf64 ai.s -o ai.o
gcc -static -Os -o example main.c ai.o
echo $?
cat example | base64 > example.b64
echo WTF
