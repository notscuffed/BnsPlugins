project(bnspatch CXX)

add_library(${PROJECT_NAME} SHARED
    "src/dllmain.cpp"
    "src/fast_wild_compare.cpp"
    "src/hooks.cpp"
    "src/xmlpatch.cpp"
    "src/xmlreader_hooks.cpp"
)

target_compile_definitions(${PROJECT_NAME}
    PRIVATE
        UNICODE
        _UNICODE
)

set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 20)

target_link_libraries_system(${PROJECT_NAME}
    PRIVATE
        pe
        pluginsdk
        fnv1a
        versioninfo
        SafeInt
        ntapi
        pugixml
        fmt
)

allow_copy_to_client(${PROJECT_NAME})
