# The Flutter tooling requires that developers have a version of Visual Studio
# with CMake 3.10 or later installed.
cmake_minimum_required(VERSION 3.10)

# Project-level configuration.
set(PROJECT_NAME "plugin_crypto")
project(${PROJECT_NAME} LANGUAGES CXX)

# This value is used when generating builds using this plugin, so it must
# not be changed.
set(PLUGIN_NAME "plugin_crypto_plugin")

# Any new source files that you add to the plugin should be added here.
list(APPEND PLUGIN_SOURCES
  "plugin_crypto_plugin.cpp"
)

# Define the plugin library target. Its name must not be changed (see comment
# on PLUGIN_NAME above).
add_library(${PLUGIN_NAME} SHARED
  ${PLUGIN_SOURCES}
)

# Apply a standard set of build settings that are configured in the
# application-level CMakeLists.txt.
apply_standard_settings(${PLUGIN_NAME})

# Symbols are hidden by default to reduce the chance of accidental conflicts
# between plugins. This should not be removed; any symbols that should be
# exported should be explicitly exported with the FLUTTER_PLUGIN_EXPORT macro.
set_target_properties(${PLUGIN_NAME} PROPERTIES
  CXX_VISIBILITY_PRESET hidden)
target_compile_definitions(${PLUGIN_NAME} PRIVATE FLUTTER_PLUGIN_IMPL)

# Source include directories and library dependencies.
target_include_directories(${PLUGIN_NAME} INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(${PLUGIN_NAME} PRIVATE flutter)

# Dormant Windows packaging setup. Windows remains disabled in pubspec.yaml
# until the pinned OpenSSL 4.x artifacts below are built and validated.
set(OPENSSL_NATIVE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../native/windows/x64")
set(OPENSSL_CRYPTO_DLL "${OPENSSL_NATIVE_DIR}/libcrypto-4-x64.dll")
set(OPENSSL_SSL_DLL "${OPENSSL_NATIVE_DIR}/libssl-4-x64.dll")

if(EXISTS "${OPENSSL_CRYPTO_DLL}" AND EXISTS "${OPENSSL_SSL_DLL}")
  set(PLUGIN_BUNDLED_LIBRARIES
    "${OPENSSL_CRYPTO_DLL}"
    "${OPENSSL_SSL_DLL}"
    PARENT_SCOPE
  )
else()
  message(WARNING
    "plugin_crypto Windows support is staged but inactive: pinned OpenSSL "
    "DLLs are missing from ${OPENSSL_NATIVE_DIR}")
  set(PLUGIN_BUNDLED_LIBRARIES PARENT_SCOPE)
endif()
