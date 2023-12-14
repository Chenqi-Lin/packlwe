cmake_minimum_required (VERSION 3.13)

project (packlwes)

set (EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

aux_source_directory (src SRC_LIST)

include_directories (include)

find_package(SEAL 4.1 REQUIRED)

add_executable (packlwes_test ${SRC_LIST})

target_link_libraries(packlwes_test SEAL::seal)