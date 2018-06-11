set(PROJECT_NAME bcr)
project(${PROJECT_NAME})
cmake_minimum_required(VERSION 3.8.2)

file(GLOB SOURCE_FILES
        "src/*.h"
        "src/*.c"
        "src/*.cpp"
        "src/ccgost/*.c"
        "src/openssl/*.c"
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
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DOPENSSL_NO_EC_NISTP_64_GCC_128")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DOPENSSL_SMALL_FOOTPRINT")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DBN_SQR_COMBA")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DOPENSSL_NO_ERR -DOPENSSL_NO_COMP -DOPENSSL_NO_GMP -DOPENSSL_NO_IDEA -DOPENSSL_NO_JPAKE -DOPENSSL_NO_LIBUNBOUND -DOPENSSL_NO_MD2 -DOPENSSL_NO_NPN -DOPENSSL_NO_PSK -DOPENSSL_NO_RC5 -DOPENSSL_NO_RFC3779 -DOPENSSL_NO_SCTP -DOPENSSL_NO_SRP -DOPENSSL_NO_SSL_TRACE -DOPENSSL_NO_SSL2 -DOPENSSL_NO_SSL3 -DOPENSSL_NO_STORE -DOPENSSL_NO_UNIT_TEST")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -m32")

#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")

add_executable(bcr ${SOURCE_FILES})
#target_link_libraries(bcr gcov)

