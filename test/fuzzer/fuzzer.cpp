// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include <evmone/evmone.h>

#include <evmc/instructions.h>
#include <intx/intx.hpp>
#include <test/utils/bytecode.hpp>
#include <test/utils/host_mock.hpp>
#include <test/utils/utils.hpp>
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <optional>


inline std::ostream& operator<<(std::ostream& os, const evmc_address& addr)
{
    return os << to_hex({addr.bytes, sizeof(addr.bytes)});
}

inline std::ostream& operator<<(std::ostream& os, const evmc_bytes32& v)
{
    return os << to_hex({v.bytes, sizeof(v.bytes)});
}

inline std::ostream& operator<<(std::ostream& os, const bytes_view& v)
{
    return os << to_hex(v);
}

[[clang::always_inline]] inline void assert_true(
    bool cond, const char* cond_str, const char* file, int line)
{
    if (!cond)
    {
        std::cerr << "ASSERTION FAILED: \"" << cond_str << "\"\n\tin " << file << ":" << line
                  << std::endl;
        __builtin_trap();
    }
}
#define ASSERT(COND) assert_true(COND, #COND, __FILE__, __LINE__)

template <typename T1, typename T2>
[[clang::always_inline]] inline void assert_eq(
    const T1& a, const T2& b, const char* a_str, const char* b_str, const char* file, int line)
{
    if (!(a == b))
    {
        std::cerr << "ASSERTION FAILED: \"" << a_str << " == " << b_str << "\"\n\twith " << a
                  << " != " << b << "\n\tin " << file << ":" << line << std::endl;
        __builtin_trap();
    }
}

#define ASSERT_EQ(A, B) assert_eq(A, B, #A, #B, __FILE__, __LINE__)

static auto print_input = std::getenv("PRINT");

extern "C" evmc_instance* evmc_create_interpreter() noexcept;

/// The reference VM.
static auto ref_vm = evmc::vm{evmc_create_evmone()};

static evmc::vm external_vms[] = {
#if ALETH
    evmc::vm{evmc_create_interpreter()},
#endif
};


class FuzzHost : public MockedHost
{
public:
    uint8_t gas_left_factor = 0;

    evmc::result call(const evmc_message& msg) noexcept override
    {
        auto result = MockedHost::call(msg);

        // Set gas_left.
        if (gas_left_factor == 0)
            result.gas_left = 0;
        else if (gas_left_factor == 1)
            result.gas_left = msg.gas;
        else
            result.gas_left = msg.gas / (gas_left_factor + 3);

        if (msg.kind == EVMC_CREATE || msg.kind == EVMC_CREATE2)
        {
            // Use the output to fill the create address.
            // We still keep the output to check if VM is going to ignore it.
            std::memcpy(result.create_address.bytes, result.output_data,
                std::min(sizeof(result.create_address), result.output_size));
        }

        return result;
    }
};


struct evm_input
{
    evmc_revision rev;
    evmc_message msg;
    FuzzHost host;
};

inline evmc_uint256be generate_interesting_value(uint8_t b) noexcept
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

inline evmc_address generate_interesting_address(uint8_t b) noexcept
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

/// Creates the block number value from 8-bit value.
/// The result is still quite small because block number affects blockhash().
inline int expand_block_number(uint8_t x) noexcept
{
    return x * 97;
}

inline int64_t expand_block_timestamp(uint8_t x) noexcept
{
    // TODO: If timestamp is -1 Aleth and evmone disagrees how to covert it to uint256.
    return x < 255 ? int64_t{16777619} * x : std::numeric_limits<int64_t>::max();
}

std::optional<evm_input> populate_input(const uint8_t* data, size_t data_size) noexcept
{
    // TODO: Move constant bytes up front, the input buffer after.
    //

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

    constexpr auto host_required_size = 9;
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
    const auto call_result_status_4bit = data[8] >> 4;
    const auto call_result_gas_left_factor_4bit = data[8] & 0x0f;

    in.host.tx_context.tx_gas_price = generate_interesting_value(gas_price_8bit);
    in.host.tx_context.tx_origin = generate_interesting_address(tx_origin_8bit);
    in.host.tx_context.block_number = expand_block_number(block_number_8bit);
    in.host.tx_context.block_timestamp = expand_block_timestamp(block_timestamp_8bit);

    auto& account = in.host.accounts[in.msg.destination];
    account.balance = generate_interesting_value(account_balance_8bit);
    const auto storage_key1 = generate_interesting_value(account_storage_key1_8bit);
    const auto storage_key2 = generate_interesting_value(account_storage_key2_8bit);
    account.storage[{}] = storage_key2;
    account.storage[storage_key1] = storage_key2;
    account.storage[storage_key2] = storage_key1;
    account.codehash = generate_interesting_value(account_codehash_8bit);
    account.code = {data, data_size};

    // Reuse the same buffer as for input.
    // TODO: We can trim it.
    in.host.call_result.status_code = static_cast<evmc_status_code>(call_result_status_4bit);
    in.host.gas_left_factor = call_result_gas_left_factor_4bit;
    in.host.call_result.output_data = in.msg.input_data;
    in.host.call_result.output_size = in.msg.input_size;

    return in;
}

inline auto hex(const evmc_address& addr) noexcept
{
    return to_hex({addr.bytes, sizeof(addr)});
}

inline evmc_status_code check_and_normalize(evmc_status_code status) noexcept
{
    ASSERT(status >= 0);
    return status <= EVMC_REVERT ? status : EVMC_FAILURE;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t data_size) noexcept
{
    auto in = populate_input(data, data_size);
    if (!in)
        return 0;

    auto& ref_host = in->host;
    const auto& code = ref_host.accounts[in->msg.destination].code;

    auto host = ref_host;  // Copy Host.

    if (print_input)
    {
        std::cout << "rev: " << int{in->rev} << "\n";
        std::cout << "code: " << to_hex(code) << "\n";
        std::cout << "decoded: " << decode(code, in->rev) << "\n";
        std::cout << "input: " << to_hex({in->msg.input_data, in->msg.input_size}) << "\n";
        std::cout << "account: " << hex(in->msg.destination) << "\n";
        std::cout << "caller: " << hex(in->msg.sender) << "\n";
        std::cout << "value: " << in->msg.value << "\n";
        std::cout << "gas: " << in->msg.gas << "\n";
        std::cout << "balance: " << in->host.accounts[in->msg.destination].balance << "\n";
        std::cout << "coinbase: " << in->host.tx_context.block_coinbase << "\n";
        std::cout << "difficulty: " << in->host.tx_context.block_difficulty << "\n";
        std::cout << "timestamp: " << in->host.tx_context.block_timestamp << "\n";
    }

    const auto ref_res = ref_vm.execute(ref_host, in->rev, in->msg, code.data(), code.size());
    const auto ref_status = check_and_normalize(ref_res.status_code);
    if (ref_status == EVMC_FAILURE)
        ASSERT_EQ(ref_res.gas_left, 0);

    for (auto& vm : external_vms)
    {
        const auto res = vm.execute(host, in->rev, in->msg, code.data(), code.size());

        const auto status = check_and_normalize(res.status_code);
        ASSERT_EQ(status, ref_status);
        ASSERT_EQ(res.gas_left, ref_res.gas_left);
        ASSERT_EQ(bytes_view(res.output_data, res.output_size),
            bytes_view(ref_res.output_data, ref_res.output_size));

        if (ref_status != EVMC_FAILURE)
        {
            ASSERT_EQ(ref_host.recorded_calls.size(), host.recorded_calls.size());

            for (size_t i = 0; i < ref_host.recorded_calls.size(); ++i)
            {
                const auto& m1 = ref_host.recorded_calls[i];
                const auto& m2 = host.recorded_calls[i];

                ASSERT_EQ(m1.kind, m2.kind);
                ASSERT_EQ(m1.flags, m2.flags);
                ASSERT_EQ(m1.depth, m2.depth);
                ASSERT_EQ(m1.gas, m2.gas);
                ASSERT_EQ(m1.destination, m2.destination);
                ASSERT_EQ(m1.sender, m2.sender);
                ASSERT_EQ(bytes_view(m1.input_data, m1.input_size),
                    bytes_view(m2.input_data, m2.input_size));
                ASSERT_EQ(m1.value, m2.value);
                ASSERT_EQ(m1.create2_salt, m2.create2_salt);
            }

            ASSERT(std::equal(ref_host.recorded_logs.begin(), ref_host.recorded_logs.end(),
                host.recorded_logs.begin(), host.recorded_logs.end()));

            ASSERT(std::equal(ref_host.recorded_blockhashes.begin(),
                ref_host.recorded_blockhashes.end(), host.recorded_blockhashes.begin(),
                host.recorded_blockhashes.end()));

            ASSERT(std::equal(ref_host.recorded_selfdestructs.begin(),
                ref_host.recorded_selfdestructs.end(), host.recorded_selfdestructs.begin(),
                host.recorded_selfdestructs.end()));

            // TODO: Enable account accesses check. Currently this is not possible because Aleth
            //       is doing additional unnecessary account existence checks in calls.
            // ASSERT(std::equal(ref_host.recorded_account_accesses.begin(),
            //     ref_host.recorded_account_accesses.end(), host.recorded_account_accesses.begin(),
            //     host.recorded_account_accesses.end()));
        }
    }

    return 0;
}
