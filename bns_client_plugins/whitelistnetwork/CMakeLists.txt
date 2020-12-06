project(whitelistnetwork CXX)

add_library(${PROJECT_NAME} SHARED
    "src/dllmain.cpp"
)

target_compile_definitions(${PROJECT_NAME}
    PRIVATE
        #DBG_CONSOLE
        UNICODE
        _UNICODE
)

set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 20)

target_include_directories(${PROJECT_NAME} PRIVATE src)

target_link_libraries_system(${PROJECT_NAME}
    PRIVATE
        pluginsdk
        pe
        fnv1a
        WIL
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        ws2_32.lib
)

allow_copy_to_client(${PROJECT_NAME})
