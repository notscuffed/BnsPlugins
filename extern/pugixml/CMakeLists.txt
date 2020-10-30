## pugixml

FetchContent_Declare(
    extern_pugixml

    GIT_REPOSITORY https://github.com/zeux/pugixml.git
    GIT_TAG        30761e48dfbd810912cf94f3eff2c410f371e0ab
)

if (NOT extern_pugixml_POPULATED)
    FetchContent_Populate(extern_pugixml)

    add_library(pugixml
        STATIC
            "${extern_pugixml_SOURCE_DIR}/src/pugixml.cpp"
    )

    target_compile_definitions(pugixml PUBLIC PUGIXML_WCHAR_MODE)

    target_include_directories(pugixml
        PUBLIC
            "${extern_pugixml_SOURCE_DIR}/src"
    )
endif()
