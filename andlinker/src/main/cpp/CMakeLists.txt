cmake_minimum_required(VERSION 3.10.2)
add_compile_options(
        -std=c++14
#        -Weverything
#        -Werror
)


file(GLOB ADL_SRC *.cpp)

add_library(adl SHARED ${ADL_SRC})

target_include_directories(adl PUBLIC include .)

target_link_libraries(adl log)