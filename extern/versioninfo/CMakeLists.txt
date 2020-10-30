## versioninfo

add_library(versioninfo STATIC versioninfo.c)
target_compile_definitions(versioninfo PRIVATE _UNICODE UNICODE)
target_link_libraries(versioninfo PRIVATE phnt)
target_include_directories(versioninfo INTERFACE "${CMAKE_CURRENT_LIST_DIR}")
