## PE

FetchContent_Declare(
    extern_pe

    GIT_REPOSITORY https://github.com/zeffy/pe.git
    GIT_TAG        18f8d7a633c641ce2be04b636b95b270cca8a3b4
)

FetchContent_MakeAvailable_Interface(extern_pe pe "/include")
target_link_libraries(pe INTERFACE ntapi phnt)
