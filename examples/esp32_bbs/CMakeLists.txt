cmake_minimum_required(VERSION 3.16)
# Find littlessh and glotui (this repo) when building the example in-tree.
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../../littlessh"
                         "${CMAKE_CURRENT_LIST_DIR}/../../glotui")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(esp32_bbs)
