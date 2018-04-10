// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "drivechain.h"

#include "crypto/sha256.h"
#include "script/interpreter.h"
#include "streams.h"
#include "util.h"

#include <algorithm>
#include <iostream>
#include <set>
#include <stdexcept>
#include <utility>
#include <vector>

std::pair<CScript::const_iterator, CScript::const_iterator> FindAckLabel(const CTransaction& coinbase)
{
    for (const CTxOut& txout : coinbase.vout) {
        const CScript& scriptPubKey = txout.scriptPubKey;
        auto result = std::search(scriptPubKey.begin(), scriptPubKey.end(), ACK_LABEL, ACK_LABEL + ACK_LABEL_LENGTH);
        if (result != scriptPubKey.end()) {
            // Skip ACK label, we know result + ACK_LABEL_LENGTH <= scriptPubKey.end()
            return std::make_pair(result + ACK_LABEL_LENGTH, scriptPubKey.end());
        }
    }
    return std::make_pair(CScript::const_iterator(nullptr), CScript::const_iterator(nullptr));
}

FullAckList ParseFullAckList(const std::vector<unsigned char>& data)
{
    try {
        FullAckList fullAckList;
        CDataStream ss(data, SER_DISK, 0);
        ss >> fullAckList;
        return fullAckList;
    } catch (...) {
    }
    return FullAckList();
}

struct ChainVote {
    std::vector<unsigned char> hash;
    uint32_t positiveAcks;
    uint32_t negativeAcks;
};

std::vector<ChainVote>::const_iterator FindPrefix(const std::vector<ChainVote>& votes, const std::vector<unsigned char>& prefix)
{
    assert(prefix.size() > 0);
    for (std::vector<ChainVote>::const_iterator itVote = votes.begin(); itVote != votes.end(); ++itVote) {
        if (memcmp(begin_ptr(itVote->hash), begin_ptr(prefix), prefix.size()) == 0) {
            return itVote;
        }
    }
    return votes.end();
}

bool CountAcks(const std::vector<unsigned char> hashSpend, const std::vector<unsigned char>& chainId, int periodAck, int periodLiveness, int& positiveAcks, int& negativeAcks, const BaseBlockReader& blockReader)
{
    int blockNumber = blockReader.GetBlockNumber();
    // Check valid block range
    if (blockNumber - periodLiveness - periodAck < 0)
        return false;
    std::vector<ChainVote> A;
    int poll_start = blockNumber - periodLiveness - periodAck;
    for (int i = poll_start; i < poll_start + periodAck; ++i) {
        CTransaction coinbase = blockReader.GetBlockCoinbase(i);
        auto result = FindAckLabel(coinbase);
        if (result.first == result.second)
            continue;
        // Parse votes
        FullAckList fullAckList = ParseFullAckList(std::vector<unsigned char>(result.first, result.second));
        for (const ChainAckList& chainAcks : fullAckList.vChainAcks) {
            // Ensure correct ChainId
            if (chainAcks.chainId != chainId)
                continue;
            std::set<uint32_t> new_acks; // votes found
            for (const Ack& ack : chainAcks.ackList.vAck) {
                std::vector<unsigned char> tx_hash = ack.prefix;
                std::vector<unsigned char> tx_hash_preimage = ack.preimage;
                // Check vote validity
                bool valid = ((tx_hash.size() <= 32) && (tx_hash_preimage.size() == 0)) ||
                             ((tx_hash.size() == 0) && (tx_hash_preimage.size() == 32));
                if ((tx_hash.size() == 32) && (tx_hash_preimage.size() == 32)) {
                    std::vector<unsigned char> hash(32);
                    // Check hash correspond to given preimage
                    CSHA256().Write(begin_ptr(tx_hash_preimage), tx_hash_preimage.size()).Finalize(begin_ptr(hash));
                    valid = memcmp(begin_ptr(hash), begin_ptr(tx_hash), 32) == 0;
                }
                if (!valid)
                    continue;
                // New proposal with empty hash
                if ((tx_hash.size() == 0) && (tx_hash_preimage.size() == 32)) {
                    tx_hash.resize(32);
                    CSHA256().Write(&tx_hash_preimage[0], tx_hash_preimage.size()).Finalize(begin_ptr(tx_hash));
                }
                // Empty hash here is a negative vote
                if (tx_hash.size() != 0) {
                    // Check existing prefix
                    auto it = FindPrefix(A, tx_hash);
                    // If it is not a prefix of a hash in A
                    if (it == A.end()) {
                        // It is a new proposal add to A
                        if (tx_hash_preimage.size() == 32) {
                            A.push_back(ChainVote{tx_hash, uint32_t(0), uint32_t(0)});
                            new_acks.insert(A.size() - 1);
                        } else {
                            if (memcmp(begin_ptr(hashSpend), begin_ptr(tx_hash), tx_hash.size()) != 0) {
                                continue;
                            }
                        }
                    } else {
                        // Existing proposal record to ack later
                        uint32_t index = it - A.begin();
                        new_acks.insert(index);
                    }
                }
            }
            // Account for votes found
            for (uint32_t k = 0; k < A.size(); ++k) {
                if (new_acks.count(k) == 1) {
                    A[k].positiveAcks++;
                } else /* if (allowed_negative_acks) */ {
                    A[k].negativeAcks++;
                }
            }
            break;
        }
    }

    // Search if hashSpend is among the proposals
    auto it = FindPrefix(A, hashSpend);
    if (it != A.end()) {
        positiveAcks = it->positiveAcks;
        negativeAcks = it->negativeAcks;
        return true;
    }
    return false;
}
