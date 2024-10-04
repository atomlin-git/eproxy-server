cmake_minimum_required(VERSION 2.8...3.15)
project(eps LANGUAGES C CXX)

if(${EPS_LIB}) 
    add_library(${PROJECT_NAME})
    target_compile_definitions(${PROJECT_NAME} PRIVATE EPS_LIBRARY)
        else() 
    add_executable(${PROJECT_NAME}) 
endif()

target_sources(${PROJECT_NAME} PRIVATE source/main.cpp)
target_include_directories(${PROJECT_NAME} PRIVATE includes)
target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_20)
