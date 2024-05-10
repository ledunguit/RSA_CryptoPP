cmake_minimum_required(VERSION 3.28)
project(RAW_RSA)

set(CMAKE_CXX_STANDARD 17)
include_directories("include")
link_directories("lib")
link_libraries("libcryptopp.a")

add_executable(RAW_RSA main.cpp)


