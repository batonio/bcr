set(PROJECT_NAME bcr)
project(${PROJECT_NAME})
cmake_minimum_required(VERSION 3.8.2)

file(GLOB SOURCE_FILES
        "src/*.cpp"
        "src/ccgost/*.h"
        "src/ccgost/*.c"
        "src/openssl/*.h"
        "src/openssl/*.c"
        "src/openssl/*.s"
        "src/openssl/bn/*.c"
        "src/openssl/buffer/*.c"
        "src/openssl/dsa/*.c"
        "src/openssl/ec/*.c"
        "src/openssl/err/*.c"
        "src/openssl/lhash/*.c"
        "src/openssl/stack/*.c")

include_directories(
        ${PROJECT_SOURCE_DIR}/src/
        ${PROJECT_SOURCE_DIR}/src/ccgost
        ${PROJECT_SOURCE_DIR}/src/openssl)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DOPENSSL_NO_RSA")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DOPENSSL_NO_DH")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DOPENSSL_NO_CMS")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DOPENSSL_NO_EC2M")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DOPENSSL_NO_FP_API")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DOPENSSL_NO_BIO")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DOPENSSL_NO_ERR")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DOPENSSL_NO_LHASH")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DOPENSSL_NO_ENGINE")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused")

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections")

add_executable(bcr ${SOURCE_FILES})

