## fmt

FetchContent_Declare(
    extern_fmt

    GIT_REPOSITORY https://github.com/fmtlib/fmt.git
    GIT_TAG        7.1.0
)

if (NOT extern_fmt_POPULATED)
    FetchContent_Populate(extern_fmt)

    add_library(fmt
        STATIC
            "${extern_fmt_SOURCE_DIR}/src/format.cc"
            "${extern_fmt_SOURCE_DIR}/src/os.cc"
    )

    target_include_directories(fmt
        PUBLIC
            "${extern_fmt_SOURCE_DIR}/include"
    )
endif()
