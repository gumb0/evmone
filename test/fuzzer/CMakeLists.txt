# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2019 The evmone Authors.
# Licensed under the Apache License, Version 2.0.

get_target_property(type evmone TYPE)
if(NOT type STREQUAL STATIC_LIBRARY)
    message(FATAL_ERROR "The evmone must be built as static library")
endif()

string(REPLACE fuzzer-no-link fuzzer CMAKE_EXE_LINKER_FLAGS ${CMAKE_EXE_LINKER_FLAGS})
add_executable(evmone-fuzzer fuzzer.cpp)
target_link_libraries(evmone-fuzzer PRIVATE evmone testutils)

target_link_directories(
    evmone-fuzzer PRIVATE
    /home/chfast/Projects/ethereum/aleth/build/fuzzing/libaleth-interpreter
    /home/chfast/Projects/ethereum/aleth/build/fuzzing/libdevcore
    /home/chfast/Projects/ethereum/aleth/build/fuzzing/aleth
    /home/chfast/Projects/ethereum/aleth/build/fuzzing/evmc/lib/instructions
)
target_link_libraries(evmone-fuzzer PRIVATE aleth-interpreter
    devcore aleth-buildinfo evmc-instructions
    /home/chfast/.hunter/_Base/c4cfcc0/a034897/5fe99df/Install/lib/libboost_filesystem-mt.a /home/chfast/.hunter/_Base/c4cfcc0/a034897/5fe99df/Install/lib/libboost_system-mt.a /home/chfast/.hunter/_Base/c4cfcc0/a034897/5fe99df/Install/lib/libboost_log-mt.a /home/chfast/.hunter/_Base/c4cfcc0/a034897/5fe99df/Install/lib/libboost_thread-mt.a /home/chfast/.hunter/_Base/c4cfcc0/a034897/5fe99df/Install/lib/libethash.a /home/chfast/.hunter/_Base/c4cfcc0/a034897/5fe99df/Install/lib/libleveldb.a /home/chfast/.hunter/_Base/c4cfcc0/a034897/5fe99df/Install/lib/libcrc32c.a /home/chfast/.hunter/_Base/c4cfcc0/a034897/5fe99df/Install/lib/libsnappy.a /home/chfast/.hunter/_Base/c4cfcc0/a034897/5fe99df/Install/lib/librocksdb.a
)