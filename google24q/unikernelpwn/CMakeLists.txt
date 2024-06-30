cmake_minimum_required(VERSION 3.28)
project(cshellcode C)

set(CMAKE_C_STANDARD 11)

add_executable(loader loader.c)


add_executable(hello_world hello_world.c)
target_compile_options(hello_world PRIVATE -nostdinc -nostdlib )

add_executable(unikernel_pid1 unikernel_pid1.c)
target_compile_options(unikernel_pid1 PRIVATE  -nostdlib )


add_executable(unikernel_pid0_stage0 unikernel_pid0_stage0.c)
target_compile_options(unikernel_pid0_stage0 PRIVATE  -nostdlib )

add_executable(unikernel_pid0_stage1 unikernel_pid0_stage1.c)
target_compile_options(unikernel_pid0_stage1 PRIVATE  -nostdlib )