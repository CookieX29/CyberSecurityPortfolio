cmake_minimum_required(VERSION 3.20)

project(CVEMonitor LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(CURL REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

add_executable(cve-monitor main.c++)

target_link_libraries(cve-monitor PRIVATE CURL::libcurl nlohmann_json::nlohmann_json)

if(MSVC)
    target_compile_options(cve-monitor PRIVATE /W4)
else()
    target_compile_options(cve-monitor PRIVATE -Wall -Wextra -Wpedantic)
endif()
