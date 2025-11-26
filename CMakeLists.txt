cmake_minimum_required(VERSION 3.6) # CMake install : https://cmake.org/download/

# add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
# add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")

# set(CMAKE_CXX_STANDARD 17)

project(MAINEXE)


# 调试信息
# add_compile_definitions(BUILD_TYPE)


# 添加第三方库 libssh2
include_directories(3rdparty/libssh2/include)
add_subdirectory(3rdparty/libssh2 libssh2)

# 添加项目
include_directories(core)
add_subdirectory(core)


# 添加主程序
add_executable(MAINEXE main.cpp)

target_link_libraries(MAINEXE libMasterUpdate)