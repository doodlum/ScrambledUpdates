cmake_minimum_required(VERSION 3.21)
project(ScrambledUpdates VERSION 1.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(COMMONLIB_PREBUILT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/extern/commonlibsse-ng"
    CACHE PATH "Extracted commonlibsse-ng-prebuilt-<tag>-all-msvc-cmake bundle")

if(NOT EXISTS "${COMMONLIB_PREBUILT_DIR}/lib/CommonLibSSE.lib")
    message(FATAL_ERROR
        "No CommonLibSSE-NG bundle at ${COMMONLIB_PREBUILT_DIR}.\n"
        "Download commonlibsse-ng-prebuilt-<tag>-all-msvc-cmake.zip from the "
        "CommonLibSSE-NG release and extract it there, or set "
        "-DCOMMONLIB_PREBUILT_DIR=<path>.")
endif()

file(READ "${COMMONLIB_PREBUILT_DIR}/TOOLSET_VERSION.txt" _baked)
string(REGEX MATCH "^([0-9]+)\.([0-9]+)" _baked "${_baked}")
math(EXPR _ours_major "${MSVC_VERSION} / 100")
math(EXPR _ours_minor "${MSVC_VERSION} % 100")
if(NOT _baked STREQUAL "${_ours_major}.${_ours_minor}")
    message(FATAL_ERROR
        "CommonLibSSE-NG bundle was built with MSVC ${_baked}, this is "
        "${_ours_major}.${_ours_minor}. Use a matching toolset or build "
        "CommonLibSSE-NG from source.")
endif()

find_package(spdlog CONFIG REQUIRED)
find_package(directxtk CONFIG REQUIRED)
find_package(directxmath CONFIG REQUIRED)

add_library(CommonLibSSE STATIC IMPORTED)
set_target_properties(CommonLibSSE PROPERTIES
    IMPORTED_CONFIGURATIONS RELEASE
    MAP_IMPORTED_CONFIG_RELWITHDEBINFO Release
    MAP_IMPORTED_CONFIG_MINSIZEREL Release
    IMPORTED_LOCATION_RELEASE "${COMMONLIB_PREBUILT_DIR}/lib/CommonLibSSE.lib"
    INTERFACE_INCLUDE_DIRECTORIES "${COMMONLIB_PREBUILT_DIR}/include;${COMMONLIB_PREBUILT_DIR}/extern/openvr/headers"
    INTERFACE_COMPILE_DEFINITIONS "ENABLE_SKYRIM_SE;ENABLE_SKYRIM_AE;ENABLE_SKYRIM_VR"
)

target_link_libraries(CommonLibSSE INTERFACE
    spdlog::spdlog
    Microsoft::DirectXTK
    Microsoft::DirectXMath
    advapi32.lib
    bcrypt.lib
    D3D11.lib
    d3dcompiler.lib
    dbghelp.lib
    DXGI.lib
    ole32.lib
    version.lib
    "${COMMONLIB_PREBUILT_DIR}/lib/openvr_api.lib"
)

add_library(ScrambledUpdates SHARED src/ScrambledUpdates.cpp)

target_precompile_headers(ScrambledUpdates PRIVATE include/PCH.h)

target_include_directories(ScrambledUpdates PRIVATE include)

target_link_libraries(ScrambledUpdates PRIVATE CommonLibSSE)

target_compile_definitions(ScrambledUpdates PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
)

target_compile_options(ScrambledUpdates PRIVATE
    /W4 /WX /permissive- /Zc:preprocessor /utf-8 /Zi
    /external:W0
)
target_link_options(ScrambledUpdates PRIVATE /DEBUG /OPT:REF /OPT:ICF)

set_target_properties(ScrambledUpdates PROPERTIES OUTPUT_NAME "ScrambledUpdates" PREFIX "")
