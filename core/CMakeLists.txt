
aux_source_directory(. CORE_SRC)

project(libMasterUpdate)

add_library(${PROJECT_NAME} STATIC ${CORE_SRC})

target_link_libraries(${PROJECT_NAME} PRIVATE libssh2)

