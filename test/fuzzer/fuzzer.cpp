// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include <evmc/evmc.hpp>
#include <evmone/evmone.h>

#include <evmc/helpers.hpp>
#include <evmc/instructions.h>
#include <intx/intx.hpp>
#include <test/utils/utils.hpp>
#include <algorithm>
#include <iostream>
#include <numeric>
#include <unordered_map>

extern "C" evmc_instance* evmc_create_interpreter() noexcept;

class Host : public evmc_context
{
public:
    evmc_address last_accessed_account = {};

    std::unordered_map<evmc_bytes32, evmc_bytes32> storage;
    bool storage_cold = true;

    evmc_tx_context tx_context = {};

    bytes log_data;
    std::vector<evmc_bytes32> log_topics;

    evmc_address selfdestruct_beneficiary = {};

    evmc_bytes32 blockhash = {};

    bool exists = false;
    intx::uint256 balance = {};
    bytes extcode = {};

    evmc_message call_msg = {};  ///< Recorded call message.
    evmc_result call_result = {};

    static evmc_host_interface interface;

    Host() noexcept : evmc_context{&interface} {}
};

evmc_host_interface Host::interface = {
    [](evmc_context* ctx, const evmc_address* addr) {
        auto& e = *static_cast<Host*>(ctx);
        e.last_accessed_account = *addr;
        return e.exists;
    },
    [](evmc_context* ctx, const evmc_address*, const evmc_bytes32* key) {
        return static_cast<Host*>(ctx)->storage[*key];
    },
    [](evmc_context* ctx, const evmc_address*, const evmc_bytes32* key, const evmc_bytes32* value) {
        auto& old = static_cast<Host*>(ctx)->storage[*key];

        evmc_storage_status status;
        if (old == *value)
            status = EVMC_STORAGE_UNCHANGED;
        else if (is_zero(old))
            status = EVMC_STORAGE_ADDED;
        else if (is_zero(*value))
            status = EVMC_STORAGE_DELETED;
        else if (static_cast<Host*>(ctx)->storage_cold)
            status = EVMC_STORAGE_MODIFIED;
        else
            status = EVMC_STORAGE_MODIFIED_AGAIN;

        old = *value;
        return status;
    },
    [](evmc_context* ctx, const evmc_address* addr) {
        auto& e = *static_cast<Host*>(ctx);
        e.last_accessed_account = *addr;
        evmc_uint256be b = {};
        intx::be::store(b.bytes, e.balance);
        return b;
    },
    [](evmc_context* ctx, const evmc_address* addr) {
        auto& e = *static_cast<Host*>(ctx);
        e.last_accessed_account = *addr;
        return e.extcode.size();
    },
    [](evmc_context* ctx, const evmc_address* addr) {
        auto& e = *static_cast<Host*>(ctx);
        e.last_accessed_account = *addr;
        auto hash = evmc_bytes32{};
        std::fill(std::begin(hash.bytes), std::end(hash.bytes), uint8_t{0xee});
        return hash;
    },
    [](evmc_context*, const evmc_address*, size_t, uint8_t*, size_t) { return size_t{0}; },
    [](evmc_context* ctx, const evmc_address*, const evmc_address* beneficiary) {
        static_cast<Host*>(ctx)->selfdestruct_beneficiary = *beneficiary;
    },
    [](evmc_context* ctx, const evmc_message* m) {
        auto& e = *static_cast<Host*>(ctx);
        e.call_msg = *m;
        return e.call_result;
    },
    [](evmc_context* ctx) { return static_cast<Host*>(ctx)->tx_context; },
    [](evmc_context* ctx, int64_t) { return static_cast<Host*>(ctx)->blockhash; },
    [](evmc_context* ctx, const evmc_address*, const uint8_t* data, size_t data_size,
        const evmc_bytes32 topics[], size_t topics_count) {
        auto& e = *static_cast<Host*>(ctx);
        e.log_data.assign(data, data_size);
        e.log_topics.reserve(topics_count);
        std::copy_n(topics, topics_count, std::back_inserter(e.log_topics));
    },
};

static auto evmone = evmc::vm{evmc_create_evmone()};
static auto aleth = evmc::vm{evmc_create_interpreter()};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t data_size) noexcept
{
    auto msg = evmc_message{};
    msg.kind = EVMC_CALL;
    msg.gas = 30000;

    auto ctx1 = Host{};
    auto ctx2 = Host{};

    auto r1 = evmone.execute(ctx1, EVMC_PETERSBURG, msg, data, data_size);
    auto r2 = aleth.execute(ctx2, EVMC_PETERSBURG, msg, data, data_size);

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
        std::cerr << "status code: " << r1.status_code << " vs " << r2.status_code << "\n";
        __builtin_trap();
    }

    if (r1.gas_left != r2.gas_left)
    {
        std::cerr << "status code: " << sc1 << "\n";
        std::cerr << r1.gas_left << " vs " << r2.gas_left << "\n";
        __builtin_trap();
    }

    if (r1.output_size != r2.output_size)
        __builtin_trap();

    return 0;
}
