cmake_minimum_required(VERSION 3.10.2)
add_compile_options(
        -std=c++14
)


file(GLOB SRC sample.cpp)

string(TOLOWER ${CMAKE_BUILD_TYPE} BUILD_TYPE_DIRNAME)

# andlinker
set(ADL_BASE ${CMAKE_CURRENT_SOURCE_DIR}/../../../../andlinker)
add_library(adl::adl SHARED IMPORTED)
set_target_properties(adl::adl PROPERTIES
        IMPORTED_LOCATION ${ADL_BASE}/build/intermediates/stripped_native_libs/${BUILD_TYPE_DIRNAME}/out/lib/${ANDROID_ABI}/libadl.so
        INTERFACE_INCLUDE_DIRECTORIES ${ADL_BASE}/src/main/cpp/include
        )

# andhooker
set(HOOKER_BASE ${CMAKE_CURRENT_SOURCE_DIR}/../../../../andhooker)
add_library(adl::hooker SHARED IMPORTED)
set_target_properties(adl::hooker PROPERTIES
        IMPORTED_LOCATION ${HOOKER_BASE}/build/intermediates/stripped_native_libs/${BUILD_TYPE_DIRNAME}/out/lib/${ANDROID_ABI}/libadlhooker.so
        INTERFACE_INCLUDE_DIRECTORIES ${HOOKER_BASE}/src/main/cpp/include
        )

add_library(sample SHARED ${SRC})

target_link_libraries(sample
        adl::adl
        adl::hooker
        log)
