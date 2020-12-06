project(loginhelper CXX)

add_library(${PROJECT_NAME} SHARED
    "src/dllmain.cpp"
    "src/game_versions/privateserver_x86.cpp"
)

target_compile_definitions(${PROJECT_NAME}
    PRIVATE
        UNICODE
        _UNICODE
)

set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 20)


target_include_directories(${PROJECT_NAME} PRIVATE src)

target_link_libraries_system(${PROJECT_NAME}
    PRIVATE
        pe
        pluginsdk
        fnv1a
        versioninfo
        WIL
        xorstr
        nspattern
)

allow_copy_to_client(${PROJECT_NAME})
