cmake_minimum_required (VERSION 2.8.11)
project(LibCOAP_CPP)

include_directories("/usr/local/include/coap")

# For mosquito library
include_directories("/usr/local/include")

set(CMAKE_CXX_FLAGS "-D_GNU_SOURCE -DWITH_POSIX -g -std=c++14")

find_package(Threads)

set(SRCS CoapServer.cpp CoapClient.cpp main.cpp)
add_executable(libcoap_cpp ${SRCS})
target_link_libraries(libcoap_cpp coap-1 ${CMAKE_THREAD_LIBS_INIT})
install(TARGETS libcoap_cpp DESTINATION bin)
