cmake_minimum_required(VERSION 3.16.3)
project(AppProtocol C)

set(CMAKE_C_STANDARD 11)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fsanitize=address")

add_executable(AppProtocol src/server.c)
