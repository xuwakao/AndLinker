cmake_minimum_required(VERSION 3.10.2)
add_compile_options(-std=c++14)

file(GLOB HOOKER_SRC *.cpp *.S)
enable_language(ASM)

# Import andlinker
set(ADL_BASE ${CMAKE_CURRENT_SOURCE_DIR}/../../../../andlinker)
string(TOLOWER ${CMAKE_BUILD_TYPE} BUILD_TYPE_DIRNAME)
add_library(adl::adl SHARED IMPORTED)
set_target_properties(adl::adl PROPERTIES
        IMPORTED_LOCATION ${ADL_BASE}/build/intermediates/stripped_native_libs/${BUILD_TYPE_DIRNAME}/out/lib/${ANDROID_ABI}/libadl.so
        INTERFACE_INCLUDE_DIRECTORIES "${ADL_BASE}/src/main/cpp/include;${ADL_BASE}/src/main/cpp"
        )

add_library(adlhooker SHARED ${HOOKER_SRC})

target_include_directories(adlhooker PUBLIC include)

target_link_libraries(adlhooker adl::adl log)
