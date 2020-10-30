include(FetchContent)
include(../cmake/FetchContentExtensions.cmake)

# Fetch content to same directory on all configurations
# to avoid redownloading per configuration
get_filename_component(fc_base "../_deps" REALPATH BASE_DIR "${CMAKE_BINARY_DIR}")
set(FETCHCONTENT_BASE_DIR ${fc_base})

add_subdirectory(pluginsdk)
add_subdirectory(sockpp)
add_subdirectory(Detours)
add_subdirectory(WIL)
add_subdirectory(phnt)
add_subdirectory(fnv1a)
add_subdirectory(PE)
add_subdirectory(ntapi)
add_subdirectory(SafeInt)
add_subdirectory(versioninfo)
add_subdirectory(pugixml)
add_subdirectory(fmt)
