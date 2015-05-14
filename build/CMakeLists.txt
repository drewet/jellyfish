cmake_minimum_required(VERSION 3.2)

set(KIT_HEADER_DIR ../rootkit)
set(KIT_SOURCE_DIR ../rootkit)

include(OpenCL.cmake)

include_directories(${KIT_HEADER_DIR})


set(KIT_HEADERS 
	${KIT_HEADER_DIR}/jelly.h 
	${KIT_HEADER_DIR}/kit.h
	${KIT_HEADER_DIR}/pcap.h
	${KIT_HEADER_DIR}/packet.h
	${KIT_HEADER_DIR}
)
set(KIT_SOURCES ${KIT_SOURCE_DIR}/kit.c)

add_library(jellyfish SHARED ${KIT_HEADERS} ${KIT_SOURCES})
target_link_libraries(jellyfish c dl OpenCL)

set(SERVER_HEADER_DIR ../server)
set(SERVER_SOURCE_DIR ../server)

set(SERVER_SOURCES ${SERVER_SOURCE_DIR}/listen.c)
set(SERVER_HEADERS)

add_executable(server ${SERVER_HEADERS} ${SERVER_SOURCES})
target_link_libraries(server c)