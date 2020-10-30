## Detours

FetchContent_Declare(
    extern_detours

    GIT_REPOSITORY https://github.com/microsoft/Detours.git
)

if (NOT extern_detours_POPULATED)
    FetchContent_Populate(extern_detours)

    add_library(Detours
        STATIC
            "${extern_detours_SOURCE_DIR}/src/creatwth.cpp"
            "${extern_detours_SOURCE_DIR}/src/detours.cpp"
            "${extern_detours_SOURCE_DIR}/src/disasm.cpp"
            "${extern_detours_SOURCE_DIR}/src/image.cpp"
            "${extern_detours_SOURCE_DIR}/src/modules.cpp"
    )

    target_include_directories(Detours
        PUBLIC
            "${extern_detours_SOURCE_DIR}/src"
    )
endif()
