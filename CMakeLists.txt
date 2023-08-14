cmake_minimum_required (VERSION 3.13)

project(Probe)

add_definitions("-Wall")

# This enables some extra warning flags that are not enabled by -Wall.
add_definitions("-Wextra")

add_executable(probe probe.cpp)
