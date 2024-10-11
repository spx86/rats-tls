project(libjson-c)

include(ExternalProject)

set(LIBJSON_C_ROOT ${CMAKE_BINARY_DIR}/external/json-c)
set(LIBJSON_SRC_PATH ${LIBJSON_C_ROOT}/src/libjson-c)
set(LIBJSON_LIB_PATH ${LIBJSON_SRC_PATH}/lib)
set(LIBJSON_INC_PATH ${LIBJSON_SRC_PATH}/include/)
set(LIBJSON_LIB_FILES ${LIBJSON_LIB_PATH}/libjson-c.a)

set(LIBJSON_C_URL https://github.com/json-c/json-c.git)
set(LIBJSON_C_CONFIGURE cd ${LIBJSON_SRC_PATH} && cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_LIBDIR=lib -DCMAKE_INSTALL_PREFIX=${LIBJSON_SRC_PATH} -DBUILD_STATIC_LIBS=on .)
set(LIBJSON_C_MAKE cd ${LIBJSON_SRC_PATH} && make)
set(LIBJSON_INSTALL cd ${LIBJSON_SRC_PATH} && make install)

ExternalProject_Add(${PROJECT_NAME}
	GIT_REPOSITORY          ${LIBJSON_C_URL}
	GIT_TAG                	41a55cfcedb54d9c1874f2f0eb07b504091d7e37
    PREFIX                  ${LIBJSON_C_ROOT}
    CONFIGURE_COMMAND       ${LIBJSON_C_CONFIGURE}
    BUILD_COMMAND           ${LIBJSON_C_MAKE}
    INSTALL_COMMAND         ${LIBJSON_INSTALL}
)

