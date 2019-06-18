// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include <evmone/evmone.h>

#include <evmc/instructions.h>
#include <intx/intx.hpp>
#include <test/utils/host_mock.hpp>
#include <test/utils/utils.hpp>
#include <algorithm>
#include <optional>
#include <iostream>

extern "C" evmc_instance* evmc_create_interpreter() noexcept;


static auto evmone = evmc::vm{evmc_create_evmone()};

#if ALETH
static auto aleth = evmc::vm{evmc_create_interpreter()};
#endif


struct evm_input
{
    evmc_revision rev;
    evmc_message msg;
};

std::optional<evm_input> populate_input(const uint8_t*& data, size_t& data_size) noexcept
{
    constexpr auto required_size = 4;
    if (data_size < required_size)
        return {};

    auto in = evm_input{};
    auto rev_4bits = data[0] >> 4;
    auto static_1bit = (data[0] >> 3) & 0b1;
    auto depth_1bit = (data[0] >> 2) & 0b1;
    auto gas_18bits = ((data[0] & 0b11) << 16) | (data[1] << 8) | data[2];  // Max 262143.
    auto input_size_8bits = data[3];

    data += required_size;
    data_size -= required_size;

    if (data_size < input_size_8bits)  // Not enough data for input.
        return {};

    in.rev = rev_4bits > EVMC_PETERSBURG ? EVMC_PETERSBURG : evmc_revision(rev_4bits);
    in.msg.flags = static_1bit ? EVMC_STATIC : 0;
    in.msg.depth = depth_1bit ? 0 : 1024;
    in.msg.gas = gas_18bits;
    in.msg.input_size = input_size_8bits;
    in.msg.input_data = data;

    data += in.msg.input_size;
    data_size -= in.msg.input_size;

    return in;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t data_size) noexcept
{
    auto in = populate_input(data, data_size);
    if (!in)
        return 0;

    auto ctx1 = MockedHost{};
    auto ctx2 = MockedHost{};

    auto r1 = evmone.execute(ctx1, EVMC_PETERSBURG, in->msg, data, data_size);

#if ALETH
    auto r2 = aleth.execute(ctx2, EVMC_PETERSBURG, in->msg, data, data_size);

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
#endif

    return 0;
}
