
# Helper macro that works similar to FetchContent_MakeAvailable
# but with EXCLUDE_FROM_ALL in add_subdirectory
macro(FetchContent_MakeAvailable_ExcludeFromAll FC_NAME)
    if (NOT ${FC_NAME}_POPULATED)
        FetchContent_Populate(${FC_NAME})
        add_subdirectory(
            ${${FC_NAME}_SOURCE_DIR}
            ${${FC_NAME}_BINARY_DIR}
            EXCLUDE_FROM_ALL
        )
    endif()
endmacro()

# Helper macro for header only libraries
macro(FetchContent_MakeAvailable_Interface FC_NAME FC_TARGET_NAME FC_INCLUDE_SUBDIR)
    if (NOT ${FC_NAME}_POPULATED)
        FetchContent_Populate(${FC_NAME})
        add_library(${FC_TARGET_NAME} INTERFACE)
        target_include_directories(${FC_TARGET_NAME}
            INTERFACE SYSTEM
                "${${FC_NAME}_SOURCE_DIR}${FC_INCLUDE_SUBDIR}")
    endif()
endmacro()