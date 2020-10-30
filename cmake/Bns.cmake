
function(allow_copy_to_client NAME)
    if(${BNSPLUGINS_COPY_TO_CLIENT})
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
	        COMMAND "${CMAKE_COMMAND}" -E
		        copy
		        "$<TARGET_FILE:${PROJECT_NAME}>"
		        "${BNSPLUGINS_CLIENT_PATH}/${BIN_FOLDER}/plugins"
        )
    endif()
endfunction()

function(allow_upload_to_server TARGET_NAME DAEMON_NAME)
    if(${BNSPLUGINS_UPLOAD_TO_SERVER})
        add_custom_command(TARGET ${TARGET_NAME} POST_BUILD
            COMMAND
                scp
                "$<TARGET_FILE:${TARGET_NAME}>"
                ${BNSPLUGINS_SERVER_HOST}:"${BNSPLUGINS_SERVER_PATH}/${DAEMON_NAME}/bin/plugins")
    endif()
endfunction()
