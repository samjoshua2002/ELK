cmake_minimum_required(VERSION 3.10)
project(SiemAgent)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Find Curl package for HTTP requests
find_package(CURL REQUIRED)

# Include directories
include_directories(include)

# Executable definition
add_executable(siem_agent src/main.cpp)

# Link necessary libraries (libcurl)
target_link_libraries(siem_agent CURL::libcurl)
