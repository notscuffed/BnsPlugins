project(PluginLoader CXX)

list(APPEND PluginLoaderType "Client" "Server" )
list(APPEND PluginLoaderLib  "winmm"  "version")

if("${CMAKE_SIZEOF_VOID_P}" STREQUAL "4")
    set(ARCH x86)
else()
    set(ARCH x64)
endif()

foreach(LOADER_TYPE LOADER_LIB IN ZIP_LISTS PluginLoaderType PluginLoaderLib)
    
    set(PLUGINLOADER_NAME ${PROJECT_NAME}${LOADER_TYPE})

    add_library(${PLUGINLOADER_NAME}
        SHARED
            "src/dllmain.cpp"
            "src/FastWildCompare.cpp"
            "src/${LOADER_LIB}_${ARCH}.def"
    )

    set_property(TARGET ${PLUGINLOADER_NAME} PROPERTY CXX_STANDARD 20)

    set_target_properties(${PLUGINLOADER_NAME}
        PROPERTIES
            LINK_FLAGS "/DELAYLOAD:${LOADER_LIB}.dll"
            OUTPUT_NAME "${LOADER_LIB}"
    )

    target_link_libraries_system(${PLUGINLOADER_NAME}
        PRIVATE
            phnt
            WIL
            pe
            ntapi
            pluginsdk
            Detours
    )

    target_link_libraries(${PLUGINLOADER_NAME}
        PRIVATE
            ${LOADER_LIB}.lib
            delayimp.lib
    )

endforeach()
