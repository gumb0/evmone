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
template <typename T1, typename T2>
[[clang::always_inline]] inline void assert_eq(const T1& a, const T2& b)
{
    if (!(a == b))
    {
        std::cerr << "Assertion failed: " << a << " != " << b << "\n";
        __builtin_trap();
    }
}

#define ASSERT_EQ(A, B) \
    if (!((A) == (B)))  \
    __builtin_trap()

static auto print_input = std::getenv("PRINT");

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
    FuzzHost host;
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

std::optional<evm_input> populate_input(const uint8_t* data, size_t data_size) noexcept
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

    constexpr auto host_required_size = 8;
    if (data_size < host_required_size)
        return {};

    const auto gas_price_8bit = data[0];
    const auto tx_origin_8bit = data[1];
    const auto block_number_8bit = data[2];
    const auto block_timestamp_8bit = data[3];
    const auto account_balance_8bit = data[4];
    const auto account_storage_key1_8bit = data[5];
    const auto account_storage_key2_8bit = data[6];
    const auto account_codehash_8bit = data[7];

    in.host.tx_context.tx_gas_price = generate_interesting_value(gas_price_8bit);
    in.host.tx_context.tx_origin = generate_interesting_address(tx_origin_8bit);
    in.host.tx_context.block_number = block_number_8bit;        // TODO: Expand to 32 bits.
    in.host.tx_context.block_timestamp = block_timestamp_8bit;  // TODO: Expand to 63 bits.

    auto& account = in.host.accounts[in.msg.destination];
    account.balance = generate_interesting_value(account_balance_8bit);
    const auto storage_key1 = generate_interesting_value(account_storage_key1_8bit);
    const auto storage_key2 = generate_interesting_value(account_storage_key2_8bit);
    account.storage[{}] = storage_key2;
    account.storage[storage_key1] = storage_key2;
    account.storage[storage_key2] = storage_key1;
    account.codehash = generate_interesting_value(account_codehash_8bit);
    account.code = {data, data_size};

    // FIXME: Add call result. Reuse input for output.

    return in;
}

auto hex(const evmc_address& addr) noexcept
{
    return to_hex({addr.bytes, sizeof(addr)});
}

bool operator==(const evmc_message& m1, const evmc_message& m2) noexcept
{
    return m1.kind == m2.kind && m1.destination == m2.destination && m1.sender == m2.sender &&
           m1.gas == m2.gas && m1.flags == m2.flags && /* FIXME: m1.depth == m2.depth && */
           m1.value == m2.value && m1.create2_salt == m2.create2_salt &&
           bytes_view{m1.input_data, m1.input_size} == bytes_view{m2.input_data, m2.input_size};
}

bool operator==(const MockedHost::log_record& l1, const MockedHost::log_record& l2) noexcept
{
    return l1.address == l2.address && l1.data == l2.data &&
           std::equal(l1.topics.begin(), l1.topics.end(), l2.topics.begin());
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t data_size) noexcept
{
    auto in = populate_input(data, data_size);
    if (!in)
        return 0;

    auto& ctx1 = in->host;
    const auto& code = ctx1.accounts[in->msg.destination].code;
    auto ctx2 = ctx1;

    if (print_input)
    {
        std::cout << "rev: " << int{in->rev} << "\n";
        std::cout << "code: " << to_hex(code) << "\n";
        std::cout << "input: " << to_hex({in->msg.input_data, in->msg.input_size}) << "\n";
        std::cout << "account: " << hex(in->msg.destination) << "\n";
        std::cout << "caller: " << hex(in->msg.sender) << "\n";
    }

    auto r1 = evmone.execute(ctx1, in->rev, in->msg, code.data(), code.size());

#if ALETH
    auto r2 = aleth.execute(ctx2, in->rev, in->msg, code.data(), code.size());

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

    if (sc1 != EVMC_FAILURE)
    {
        if (ctx1.recorded_calls.size() != ctx2.recorded_calls.size())
            __builtin_trap();

        for (size_t i = 0; i < ctx1.recorded_calls.size(); ++i)
        {
            const auto& m1 = ctx1.recorded_calls[i];
            const auto& m2 = ctx2.recorded_calls[i];

            ASSERT_EQ(m1.kind, m2.kind);
            assert_eq(m1.depth, m2.depth);
            ASSERT_EQ(m1.flags, m2.flags);
            ASSERT_EQ(m1.gas, m2.gas);
            ASSERT_EQ(m1.destination, m2.destination);
            ASSERT_EQ(m1.sender, m2.sender);

            if (!(ctx1.recorded_calls[i] == ctx2.recorded_calls[i]))
            {
                std::cerr << "recorded call [" << i << "]:\n";

                __builtin_trap();
            }
        }

        if (!std::equal(
                ctx1.recorded_logs.begin(), ctx1.recorded_logs.end(), ctx2.recorded_logs.begin()))
            __builtin_trap();
    }
#endif

    return 0;
}
