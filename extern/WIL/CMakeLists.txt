## WIL

SET(WIL_BUILD_TESTS OFF CACHE INTERNAL "")
SET(WIL_BUILD_PACKAGING OFF CACHE INTERNAL "")

FetchContent_Declare(
    extern_wil

    GIT_REPOSITORY https://github.com/microsoft/wil.git
    GIT_TAG        c5d2efe677467d8d8bf66226e42d5fc2d4b66613
)

FetchContent_MakeAvailable_ExcludeFromAll(extern_wil)
