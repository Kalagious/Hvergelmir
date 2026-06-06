cmake_minimum_required(VERSION 3.15)
project(SecureAgeOverflow LANGUAGES CXX)

file(GLOB SEC_SRCS "*.cpp")

add_executable(SecureAgeOverflow ${SEC_SRCS})

target_link_libraries(SecureAgeOverflow PRIVATE Hvergelmir)

target_compile_features(SecureAgeOverflow PUBLIC cxx_std_17)
