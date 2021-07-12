# Root CMake file for NDN-Lite over POSIX
cmake_minimum_required (VERSION 3.5)
project(ndn-lite)

option(BUILD_DOCS "Build documentation" OFF)
option(DYNAMIC_LIB "Build dynamic link library" OFF)
option(BUILD_PYTHON "Build python bindings" OFF)

if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE DEBUG)
endif()

add_definitions(-D_GNU_SOURCE)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -Werror -Wno-format -Wno-int-to-pointer-cast -Wunused-parameter -Wunused-variable")
set(CMAKE_C_FLAGS_DEBUG "-O0 -ggdb")
set(CMAKE_C_FLAGS_RELEASE "-O3")

set(DIR_CMAKEFILES "${PROJECT_SOURCE_DIR}/CMakeInputs")
set(DIR_NDN_LITE "${PROJECT_SOURCE_DIR}/ndn-lite")
set(DIR_ADAPTATION "${PROJECT_SOURCE_DIR}/adaptation")
set(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}")
include_directories(${PROJECT_SOURCE_DIR})

# NDN-Lite static library
if(DYNAMIC_LIB)
  add_library(ndn-lite SHARED)
else()
  add_library(ndn-lite STATIC)
endif()
include(${DIR_CMAKEFILES}/ndnlite.cmake)
target_compile_options(ndn-lite PRIVATE -Werror)

# Adaptation
include(${DIR_CMAKEFILES}/adaptation.cmake)

# Unit test program
add_executable(unittest ndn-lite.h)
target_link_libraries(unittest ndn-lite)
include(${DIR_CMAKEFILES}/unittest.cmake)

# Copy headers
include(GNUInstallDirs)
install(DIRECTORY "${PROJECT_SOURCE_DIR}/ndn-lite"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
        FILES_MATCHING
        PATTERN "*.h"
)

install(FILES "${PROJECT_SOURCE_DIR}/ndn-lite.h"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

install(TARGETS ndn-lite
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
)
