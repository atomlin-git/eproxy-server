cmake_minimum_required(VERSION 2.8...3.15)
project(eps LANGUAGES C CXX)

if(${EPS_LIB}) 
    add_library(${PROJECT_NAME} INTERFACE)
    target_include_directories(${PROJECT_NAME} PUBLIC INTERFACE includes)
    target_compile_features(${PROJECT_NAME} PRIVATE INTERFACE cxx_std_20)
        else() 
    add_executable(${PROJECT_NAME}) 
    target_sources(${PROJECT_NAME} PRIVATE source/main.cpp)
    target_include_directories(${PROJECT_NAME} PRIVATE includes)
    target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_20)
endif()

target_compile_options(${PROJECT_NAME} PRIVATE INTERFACE
    -fstack-protector-strong        
    -D_FORTIFY_SOURCE=2             
    -fPIE                           
)

if(NOT MSVC)
    target_link_options(${PROJECT_NAME} PRIVATE INTERFACE -pie)
endif()

if(APPLE) 
    option(ENABLE_ASAN "Enable Address Sanitizer" TRUE)
    if(ENABLE_ASAN)
        target_compile_options(${PROJECT_NAME} PRIVATE -fsanitize=address,undefined)
        target_link_options(${PROJECT_NAME} PRIVATE -fsanitize=address,undefined)
    endif()

    option(ENABLE_TSAN "Enable Thread Sanitizer" TRUE)
    if(ENABLE_TSAN)
        target_compile_options(${PROJECT_NAME} PRIVATE -fsanitize=thread)
        target_link_options(${PROJECT_NAME} PRIVATE -fsanitize=thread)
    endif()
endif()