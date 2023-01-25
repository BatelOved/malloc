cmake_minimum_required(VERSION 3.0.0)
project(malloc VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 11)

include(CTest)
enable_testing()

add_executable(malloc main.cpp malloc_1.h malloc_2.h malloc_3.h)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
