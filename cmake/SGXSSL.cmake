# Project name
if(SGX)
    project(intel-sgx-ssl)
endif()

include(ExternalProject)
include(FindSGXSSL)

# Patch
set(SGX_SSL_PATCH_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/external/sgx-ssl")
set(_patch_script "${SGX_SSL_PATCH_DIR}/patch_script.sh")
file(WRITE "${_patch_script}"
"#!/bin/sh
cd ${INTEL_SGXSSL_SRC}/
if [ ! -e  Linux/sgx/libsgx_usgxssl/uunistd.cpp ]; then
        patch -p1 < ${SGX_SSL_PATCH_DIR}/patch/0001-add-ssl-library-enclave-support.patch;
fi;
")

set(_patch_cmake "${SGX_SSL_PATCH_DIR}/patch.cmake")
file(WRITE "${_patch_cmake}"
        "execute_process(COMMAND sh ${_patch_script} WORKING_DIRECTORY ${SGX_SSL_PATCH_DIR})"
)

# Configure
set(_configure_script "${SGX_SSL_PATCH_DIR}/download_script.sh")
file(WRITE "${_configure_script}"
"#!/bin/sh
if [ ! -e ${OPENSSL_DIR}/openssl-1.1.1*.tar.gz ]; then
        wget --no-check-certificate https://www.openssl.org/source/openssl-1.1.1k.tar.gz -P ${OPENSSL_DIR};
fi;
")

set(_configure_cmake "${SGX_SSL_PATCH_DIR}/configure.cmake")
file(WRITE "${_configure_cmake}"
	"execute_process(COMMAND sh ${_configure_script} WORKING_DIRECTORY ${SGX_SSL_PATCH_DIR})"
)

# Make
set(_make_script "${SGX_SSL_PATCH_DIR}/intel_sgxssl_make.sh")
if(SGX)
    file(WRITE "${_make_script}"
"#!/bin/sh
if [ ! -d ${INTEL_SGXSSL_LIB_PATH} -o ! -e ${INTEL_SGXSSL_LIB_PATH}/libsgx_usgxssl.a ]; then
        cd ${INTEL_SGXSSL_SRC}/Linux;
        make -j$(nproc)
fi;
")
endif()

set(_make_cmake "${SGX_SSL_PATCH_DIR}/make.cmake")
file(WRITE "${_make_cmake}"
        "execute_process(COMMAND sh ${_make_script} WORKING_DIRECTORY ${SGX_SSL_PATCH_DIR})"
)

# Install
set(_install_script "${SGX_SSL_PATCH_DIR}/sgxssl_install.sh")
if(SGX)
    file(WRITE "${_install_script}"
"#!/bin/sh
cd ${INTEL_SGXSSL_SRC}/Linux
install -d -m 0755 ${INTEL_SGXSSL_LIB_PATH}
install -m 0755 ${INTEL_SGXSSL_LIB}/libsgx_usgxssl.a ${INTEL_SGXSSL_LIB_PATH}/libsgx_usgxssl.a
install -m 0755 ${INTEL_SGXSSL_LIB}/libsgx_tsgxssl.a ${INTEL_SGXSSL_LIB_PATH}/libsgx_tsgxssl.a
install -m 0755 ${INTEL_SGXSSL_LIB}/libsgx_tsgxssl_crypto.a ${INTEL_SGXSSL_LIB_PATH}/libsgx_tsgxssl_crypto.a
install -m 0755 ${INTEL_SGXSSL_LIB}/libsgx_tsgxssl_ssl.a ${INTEL_SGXSSL_LIB_PATH}/libsgx_tsgxssl_ssl.a
#sudo make install DESTDIR=/opt/rats-tls/sgxssl/
cd -
")
endif()

set(_install_cmake "${SGX_SSL_PATCH_DIR}/install.cmake")
file(WRITE "${_install_cmake}"
        "execute_process(COMMAND sh ${_install_script} WORKING_DIRECTORY ${SGX_SSL_PATCH_DIR})"
)

SET_DIRECTORY_PROPERTIES(PROPERTIES CLEAN_NO_CUSTOM 1)

# Set intel-sgx-ssl git and compile parameters
set(SGXSSL_URL           https://github.com/intel/intel-sgx-ssl.git)

ExternalProject_Add(${PROJECT_NAME}
        GIT_REPOSITORY          ${SGXSSL_URL}
        GIT_TAG                 1e51eacc0de8cdd541fad05487e1db93c0c56540
        PREFIX                  ${INTEL_SGXSSL_ROOT}
        PATCH_COMMAND           ${CMAKE_COMMAND} -P ${_patch_cmake}
        CONFIGURE_COMMAND       ${CMAKE_COMMAND} -P ${_configure_cmake}
        BUILD_COMMAND           ${CMAKE_COMMAND} -P ${_make_cmake}
        INSTALL_COMMAND         ${CMAKE_COMMAND} -P ${_install_cmake}
)
