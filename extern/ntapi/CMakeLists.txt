## ntapi

FetchContent_Declare(
    extern_ntapi

    GIT_REPOSITORY https://github.com/zeffy/ntapi.git
    GIT_TAG        500c9eee78be8f2cb4a3f0262c5ca4b851fdb310
)

FetchContent_MakeAvailable_Interface(extern_ntapi ntapi "/include")
target_link_libraries(ntapi INTERFACE WIL)
