cmake_minimum_required(VERSION 3.20)
project(librarian)
project(demo)

set(CMAKE_CXX_STANDARD 20)

add_library(demo SHARED
        demo.cpp)
add_executable(librarian
        main.cpp inject.cpp)
