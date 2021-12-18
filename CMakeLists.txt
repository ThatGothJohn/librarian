cmake_minimum_required(VERSION 3.20)
project(librarian)
project(demo)
project(runnable)

set(CMAKE_CXX_STANDARD 20)

add_library(demo SHARED
        demo.cpp librarian)
add_library(librarian SHARED
        librarian.cpp)
add_executable(runnable
        main.cpp librarian demo)