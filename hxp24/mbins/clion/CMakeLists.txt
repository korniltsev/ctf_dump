cmake_minimum_required(VERSION 3.30)
project(clion C)

set(CMAKE_C_STANDARD 11)

add_executable(clion main.c)
add_executable(decomp decomp.c)
add_executable(pg pg.c)
