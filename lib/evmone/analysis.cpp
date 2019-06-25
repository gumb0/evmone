// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include "analysis.hpp"

#include <evmc/instructions.h>

namespace evmone
{
namespace
{
bool is_terminator(uint8_t c) noexcept
{
    return c == OP_JUMP || c == OP_JUMPI || c == OP_STOP || c == OP_RETURN || c == OP_REVERT ||
           c == OP_SELFDESTRUCT;
}
}  // namespace

int code_analysis::find_jumpdest(int offset) const noexcept
{
    // TODO: Replace with lower_bound().
    for (const auto& d : jumpdest_map)
    {
        if (d.first == offset)
            return d.second;
    }
    return -1;
}

evmc_call_kind op2call_kind(uint8_t opcode) noexcept
{
    switch (opcode)
    {
    case OP_CREATE:
        return EVMC_CREATE;
    case OP_CALL:
        return EVMC_CALL;
    case OP_CALLCODE:
        return EVMC_CALLCODE;
    case OP_DELEGATECALL:
        return EVMC_DELEGATECALL;
    case OP_CREATE2:
        return EVMC_CREATE2;
    default:
        return evmc_call_kind(-1);
    }
}

code_analysis analyze(
    const exec_fn_table& fns, evmc_revision rev, const uint8_t* code, size_t code_size) noexcept
{
    code_analysis analysis;
    // TODO: Check if final result exceeds the reservation.
    analysis.instrs.reserve(code_size + 1);

    auto* instr_table = evmc_get_instruction_metrics_table(rev);

    block_info* block = nullptr;
    int instr_index = 0;
    for (size_t i = 0; i < code_size; ++i, ++instr_index)
    {
        // TODO: Loop in reverse order for easier GAS analysis.
        const auto c = code[i];

        const bool jumpdest = c == OP_JUMPDEST;

        if (!block || jumpdest)
        {
            // Create new block.
            block = &analysis.blocks.emplace_back();

            // Create BEGINBLOCK instruction which either replaces JUMPDEST or is injected
            // in case there is no JUMPDEST.
            analysis.instrs.emplace_back(fns[OPX_BEGINBLOCK]);

            if (jumpdest)  // Add the jumpdest to the map.
                analysis.jumpdest_map.emplace_back(static_cast<int>(i), instr_index);
            else  // Increase instruction count because additional BEGINBLOCK was injected.
                ++instr_index;

            analysis.instrs.emplace_back(static_cast<int>(analysis.blocks.size() - 1));
            ++instr_index;
        }

        if (!jumpdest)
            analysis.instrs.emplace_back(fns[c]);

        auto metrics = instr_table[c];
        block->gas_cost += metrics.gas_cost;
        auto stack_req = metrics.num_stack_arguments - block->stack_diff;
        block->stack_diff += (metrics.num_stack_returned_items - metrics.num_stack_arguments);
        block->stack_req = std::max(block->stack_req, stack_req);
        block->stack_max = std::max(block->stack_max, block->stack_diff);

        // Skip PUSH data.
        if (c >= OP_PUSH1 && c <= OP_PUSH32)
        {
            // OPT: bswap data here.
            ++i;
            const auto push_size = size_t(c - OP_PUSH1 + 1);
            auto data = bytes32{};

            const auto leading_zeros = 32 - push_size;
            for (size_t j = 0; j < push_size && (i + j) < code_size; ++j)
                data[leading_zeros + j] = code[i + j];
            i += push_size - 1;

            const auto value = intx::be::uint256(&data[0]);
            analysis.instrs.emplace_back(value.lo.lo);
            analysis.instrs.emplace_back(value.lo.hi);
            analysis.instrs.emplace_back(value.hi.lo);
            analysis.instrs.emplace_back(value.hi.hi);
            instr_index += 4;
        }
        else if (c >= OP_DUP1 && c <= OP_DUP16)
        {
            analysis.instrs.emplace_back(c - OP_DUP1);
            ++instr_index;
        }
        else if (c >= OP_SWAP1 && c <= OP_SWAP16)
        {
            analysis.instrs.emplace_back(c - OP_SWAP1 + 1);
            ++instr_index;
        }
        else if (c == OP_GAS)
        {
            analysis.instrs.emplace_back(static_cast<int>(block->gas_cost));
            ++instr_index;
        }
        else if (c == OP_DELEGATECALL || c == OP_CALL || c == OP_CALLCODE || c == OP_STATICCALL ||
                 c == OP_CREATE || c == OP_CREATE2)
        {
            const auto gas = static_cast<int>(block->gas_cost);
            const auto call_kind = op2call_kind(c == OP_STATICCALL ? uint8_t{OP_CALL} : c);
            analysis.instrs.emplace_back(gas, call_kind);
            ++instr_index;
        }
        else if (c == OP_PC)
        {
            analysis.instrs.emplace_back(static_cast<int>(i));
            ++instr_index;
        }
        else if (c >= OP_LOG0 && c <= OP_LOG4)
        {
            analysis.instrs.emplace_back(c - OP_LOG0);
            ++instr_index;
        }
        else if (is_terminator(c))
            block = nullptr;
    }

    // Not terminated block or empty code.
    if (block || code_size == 0 || code[code_size - 1] == OP_JUMPI)
        analysis.instrs.emplace_back(fns[OP_STOP]);

    return analysis;
}

}  // namespace evmone
