cmake_minimum_required(VERSION 3.3)
project(stm32w_wireshark)

set(SOURCE_FILES main.c)
add_executable(stm32w-wireshark ${SOURCE_FILES})

target_link_libraries(stm32w-wireshark rt)