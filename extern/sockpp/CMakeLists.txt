## sockpp

FetchContent_Declare(
    extern_sockpp

    GIT_REPOSITORY https://github.com/fpagliughi/sockpp.git
    GIT_TAG        v0.7
)

SET(SOCKPP_BUILD_STATIC OFF CACHE INTERNAL "")

FetchContent_MakeAvailable_ExcludeFromAll(extern_sockpp)

target_compile_definitions(sockpp-objs
    PRIVATE
        _WINSOCK_DEPRECATED_NO_WARNINGS
)
