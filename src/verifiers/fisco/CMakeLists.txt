project(verifier_fisco)

# Set include directory
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../include 
				 ${CMAKE_CURRENT_SOURCE_DIR}/../../include/fisco 
				 ${CMAKE_CURRENT_SOURCE_DIR}
				 ${LIBBCOS_C_SDK_INC_PATH}
				 #				 ${LIBJSON_INC_PATH}
				 /usr/include 
                 )
include_directories(${INCLUDE_DIRS})

# Set dependency library directory
set(LIBRARY_DIRS ${CMAKE_BINARY_DIR}/src
                 ${RATS_TLS_INSTALL_LIB_PATH}
				 ${LIBBCOS_C_SDK_LIB_PATH}
				 #				 ${LIBJSON_LIB_PATH} 
                 )
link_directories(${LIBRARY_DIRS})

# Set source file
set(SOURCES crud.c
            p256.c
			did.c
            )

add_library(${PROJECT_NAME} SHARED ${SOURCES})
target_link_libraries(${PROJECT_NAME} ${RATS_TLS_LDFLAGS} libbcos-c-sdk.so json-c)
set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${VERSION} SOVERSION ${VERSION_MAJOR})

# Install library
install(TARGETS ${PROJECT_NAME}
	DESTINATION ${RATS_TLS_INSTALL_LIBV_PATH})
