cmake_minimum_required(VERSION 2.8...3.15)
project(eps LANGUAGES C CXX)

if(${EPS_LIB}) 
    add_library(${PROJECT_NAME} INTERFACE)
        else() 
    add_executable(${PROJECT_NAME}) 
    target_sources(${PROJECT_NAME} PRIVATE source/main.cpp)
endif()

target_include_directories(${PROJECT_NAME} PUBLIC includes)
target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_20)
