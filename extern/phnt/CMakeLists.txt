## ProcessHacker's phnt

FetchContent_Declare(
    extern_processhacker

    GIT_REPOSITORY https://github.com/processhacker/processhacker.git
)

FetchContent_MakeAvailable_Interface(extern_processhacker phnt "/phnt/include")

target_link_libraries(phnt
    INTERFACE
        ntdll.lib
)

target_compile_definitions(phnt
    INTERFACE
        NOMINMAX
)