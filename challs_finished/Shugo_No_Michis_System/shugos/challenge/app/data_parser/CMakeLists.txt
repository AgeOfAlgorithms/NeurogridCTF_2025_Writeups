cmake_minimum_required(VERSION 3.12)
project(data_parser C CXX)
set(CMAKE_CXX_STANDARD 17)

find_package(Threads REQUIRED)
find_package(PostgreSQL REQUIRED)  # provides PostgreSQL_LIBRARIES and _INCLUDE_DIRS

add_executable(data_parser
  src/main.cpp
  src/env.cpp
)

target_include_directories(data_parser PRIVATE
  ${PostgreSQL_INCLUDE_DIRS}
  src
)

target_link_libraries(data_parser PRIVATE
  ${PostgreSQL_LIBRARIES}
  Threads::Threads
)
