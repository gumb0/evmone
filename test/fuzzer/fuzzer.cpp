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
#include <optional>

extern "C" evmc_instance* evmc_create_interpreter() noexcept;


static auto evmone = evmc::vm{evmc_create_evmone()};

#if ALETH
static auto aleth = evmc::vm{evmc_create_interpreter()};
#endif


class FuzzHost : public MockedHost
{
};


struct evm_input
{
    evmc_revision rev;
    evmc_message msg;
};

evmc_uint256be generate_interesting_value(uint8_t b) noexcept
{
    const auto s = (b >> 6) & 0b11;
    const auto fill = (b >> 5) & 0b1;
    const auto above = (b >> 4) & 0b1;
    const auto val = b & 0b1111;

    auto z = evmc_uint256be{};

    const auto size = s == 0 ? 1 : 1 << (s + 2);

    if (fill)
    {
        for (auto i = sizeof(z) - size; i < sizeof(z); ++i)
            z.bytes[i] = 0xff;
    }

    if (above)
        z.bytes[sizeof(z) - size % sizeof(z) - 1] ^= val;
    else
        z.bytes[sizeof(z) - size] ^= val << 4;

    return z;
}

evmc_address generate_interesting_address(uint8_t b) noexcept
{
    const auto s = (b >> 6) & 0b11;
    const auto fill = (b >> 5) & 0b1;
    const auto above = (b >> 4) & 0b1;
    const auto val = b & 0b1111;

    auto z = evmc_address{};

    const auto size = s == 3 ? 20 : 1 << s;

    if (fill)
    {
        for (auto i = sizeof(z) - size; i < sizeof(z); ++i)
            z.bytes[i] = 0xff;
    }

    if (above)
        z.bytes[sizeof(z) - size % sizeof(z) - 1] ^= val;
    else
        z.bytes[sizeof(z) - size] ^= val << 4;

    return z;
}

std::optional<evm_input> populate_input(const uint8_t*& data, size_t& data_size) noexcept
{
    constexpr auto required_size = 7;
    if (data_size < required_size)
        return {};

    auto in = evm_input{};
    const auto rev_4bits = data[0] >> 4;
    const auto static_1bit = (data[0] >> 3) & 0b1;
    const auto depth_1bit = (data[0] >> 2) & 0b1;
    const auto gas_18bits = ((data[0] & 0b11) << 16) | (data[1] << 8) | data[2];  // Max 262143.
    const auto input_size_8bits = data[3];
    const auto destination_8bits = data[4];
    const auto sender_8bits = data[5];
    const auto value_8bits = data[6];

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
    in.msg.destination = generate_interesting_address(destination_8bits);
    in.msg.sender = generate_interesting_address(sender_8bits);
    in.msg.value = generate_interesting_value(value_8bits);

    data += in.msg.input_size;
    data_size -= in.msg.input_size;

    return in;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t data_size) noexcept
{
    auto in = populate_input(data, data_size);
    if (!in)
        return 0;

    auto ctx1 = FuzzHost{};
    auto ctx2 = ctx1;

    auto r1 = evmone.execute(ctx1, in->rev, in->msg, data, data_size);

#if ALETH
    auto r2 = aleth.execute(ctx2, in->rev, in->msg, data, data_size);

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
