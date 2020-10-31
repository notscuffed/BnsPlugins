## nspattern

add_library(nspattern STATIC pattern.cpp)
target_include_directories(nspattern PUBLIC "${CMAKE_CURRENT_LIST_DIR}")

set_property(TARGET nspattern PROPERTY CXX_STANDARD 20)
