project(lesslogging CXX)

add_library(${PROJECT_NAME} SHARED
    "src/dllmain.cpp"
)

set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 20)

target_link_libraries_system(${PROJECT_NAME}
    PRIVATE
        pe
        pluginsdk
)

allow_upload_to_server(${PROJECT_NAME} GameDaemon01)
