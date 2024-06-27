cmake_minimum_required(VERSION 2.8...3.15)
project(eps LANGUAGES C CXX)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CMAKE_CXX_STANDARD 20)

include_directories(includes)
add_executable(${PROJECT_NAME}) 
target_sources(${PROJECT_NAME} PRIVATE source/main.cpp)
target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_20)