cmake_minimum_required(VERSION 3.10.2)
add_compile_options(
        -std=c++14
)


file(GLOB SRC sample.cpp)

string(TOLOWER ${CMAKE_BUILD_TYPE} BUILD_TYPE_DIRNAME)
set(ADL_BASE ${CMAKE_CURRENT_SOURCE_DIR}/../../../../andlinker)
add_library(adl::adl SHARED IMPORTED)
set_target_properties(adl::adl PROPERTIES
        IMPORTED_LOCATION ${ADL_BASE}/build/intermediates/stripped_native_libs/${BUILD_TYPE_DIRNAME}/out/lib/${ANDROID_ABI}/libadl.so
        INTERFACE_INCLUDE_DIRECTORIES ${ADL_BASE}/src/main/cpp/include
        )

add_library(sample SHARED ${SRC})

target_link_libraries(sample
        adl::adl
        log)