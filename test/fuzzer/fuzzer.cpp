// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include <evmone/evmone.h>

#include <evmc/instructions.h>
#include <intx/intx.hpp>
#include <test/utils/host_mock.hpp>
#include <test/utils/utils.hpp>
#include <algorithm>
#include <iostream>
#include <numeric>
#include <unordered_map>

extern "C" evmc_instance* evmc_create_interpreter() noexcept;


static auto evmone = evmc::vm{evmc_create_evmone()};
static auto aleth = evmc::vm{evmc_create_interpreter()};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t data_size) noexcept
{
    if (data_size < 3)
        return 0;


    auto msg = evmc_message{};
    msg.kind = EVMC_CALL;
    msg.gas = (data[0] << 8) | data[1];

    msg.input_size = data[2];
    msg.input_data = &data[3];
    if (data_size - 3 < msg.input_size)
        return 0;

    auto code = &data[3 + msg.input_size];
    auto code_size = data_size - (3 + msg.input_size);

    auto ctx1 = MockedHost{};
    auto ctx2 = MockedHost{};

    auto r1 = evmone.execute(ctx1, EVMC_PETERSBURG, msg, code, code_size);
    auto r2 = aleth.execute(ctx2, EVMC_PETERSBURG, msg, code, code_size);

    auto sc1 = r1.status_code;
    if (sc1 < 0)
        __builtin_trap();
    if (sc1 != EVMC_SUCCESS && sc1 != EVMC_REVERT)
        sc1 = EVMC_FAILURE;

    auto sc2 = r2.status_code;
    if (sc2 < 0)
        __builtin_trap();
    if (sc2 != EVMC_SUCCESS && sc2 != EVMC_REVERT)
        sc2 = EVMC_FAILURE;

    if (sc1 != sc2)
    {
        std::cerr << "status code: evmone:" << r1.status_code << " vs aleth:" << r2.status_code
                  << "\n";
        __builtin_trap();
    }

    if (r1.gas_left != r2.gas_left)
    {
        std::cerr << "status code: " << sc1 << "\n";
        std::cerr << r1.gas_left << " vs " << r2.gas_left << "\n";
        __builtin_trap();
    }

    if (bytes_view{r1.output_data, r1.output_size} != bytes_view{r2.output_data, r2.output_size})
        __builtin_trap();

    return 0;
}
