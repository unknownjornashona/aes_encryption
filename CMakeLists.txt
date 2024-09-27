cmake_minimum_required(VERSION 3.10)

# 设置项目名称和版本
project(AESFileEncryption VERSION 1.0)

# 查找 OpenSSL 库
find_package(OpenSSL REQUIRED)

# 包含头文件目录
include_directories(include)

# 设置源文件和可执行文件
set(SOURCES
    src/aes_file_encryption.cpp
    src/main.cpp
)

# 添加可执行文件
add_executable(aes_file_encryption ${SOURCES})

# 链接 OpenSSL 库
target_link_libraries(aes_file_encryption OpenSSL::SSL OpenSSL::Crypto)

# 设置 C++ 标准
set_target_properties(aes_file_encryption PROPERTIES
    CXX_STANDARD 11
    CXX_STANDARD_REQUIRED YES
)

# 添加测试可执行文件
set(TEST_SOURCES
    tests/test_aes_file_encryption.cpp
)

enable_testing()  # 启用测试

add_executable(test_aes_file_encryption ${TEST_SOURCES})

# 链接 OpenSSL 库给测试
target_link_libraries(test_aes_file_encryption OpenSSL::SSL OpenSSL::Crypto)

# 设置 C++ 标准
set_target_properties(test_aes_file_encryption PROPERTIES
    CXX_STANDARD 11
    CXX_STANDARD_REQUIRED YES
)

# 添加测试到 CMake 测试
add_test(NAME test_aes_file_encryption COMMAND test_aes_file_encryption)

# 添加安装目标
install(TARGETS aes_file_encryption test_aes_file_encryption
    RUNTIME DESTINATION bin
)

# 安装文档
install(FILES INSTALL.md COPYRIGHT.md README.md LICENSE DESTINATION share/AESFileEncryption)

# 生成构建目录提示
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
