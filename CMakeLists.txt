cmake_minimum_required(VERSION 3.11 FATAL_ERROR)
project(BnsPlugins)

include(cmake/TargetLinkLibrariesSystem.cmake)
include(cmake/Bns.cmake)

if("${CMAKE_SIZEOF_VOID_P}" STREQUAL "4")
    set(BIN_FOLDER "bin")
else()
    set(BIN_FOLDER "bin64")
endif()

option(BNSPLUGINS_UPLOAD_TO_SERVER "Upload to server plugins to server after build?" OFF)
set(BNSPLUGINS_SERVER_HOST "" CACHE STRING "Upload destination host. Example: 'administrator@host.com'")
set(BNSPLUGINS_SERVER_PATH "" CACHE STRING "Path on destination server. Example: 'D:/service/GameDaemon01/bin/plugins'")

option(BNSPLUGINS_COPY_TO_CLIENT "Copy plugins to client after build?" OFF)
set(BNSPLUGINS_CLIENT_PATH "" CACHE STRING "Client root folder path. Example: 'D:/BNS/Client'")

if(${BNSPLUGINS_UPLOAD_TO_SERVER})
    message("[${PROJECT_NAME}] Enabled uploading to server. Destination: ${BNSPLUGINS_SERVER_HOST}:${BNSPLUGINS_SERVER_PATH}/\${DaemonName}/bin/plugins")
endif()

if(${BNSPLUGINS_COPY_TO_CLIENT})
    message("[${PROJECT_NAME}] Enabled copying to client plugins folder. Destination: ${BNSPLUGINS_CLIENT_PATH}/${BIN_FOLDER}/plugins")
endif()

add_subdirectory(extern)
add_subdirectory(plugin_loader)

add_subdirectory(bns_client_plugins/antigg)
add_subdirectory(bns_client_plugins/bnspatch)

add_subdirectory(bns_server_plugins/lesslogging)
