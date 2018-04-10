// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_DRIVECHAIN_H
#define BITCOIN_SCRIPT_DRIVECHAIN_H

#include "serialize.h"
#include "primitives/transaction.h"
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>

#define LIMITED_VECTOR(obj, n) REF(MakeLimitedVector<n>(obj))

const unsigned char ACK_LABEL[] = {0x41, 0x43, 0x4B, 0x3A}; // "ACK:"
const size_t ACK_LABEL_LENGTH = sizeof(ACK_LABEL);

template <size_t Limit, typename U>
class LimitedVector
{
protected:
    std::vector<U>& vec;

public:
    LimitedVector(std::vector<U>& vec) : vec(vec) {}

    template <typename Stream>
    void Unserialize(Stream& s, int, int = 0)
    {
        size_t size = ReadCompactSize(s);
        if (size > Limit) {
            throw std::ios_base::failure("String length limit exceeded");
        }
        vec.resize(size);
        if (size != 0)
            s.read((char*)&vec[0], size);
    }

    template <typename Stream>
    void Serialize(Stream& s, int, int = 0) const
    {
        WriteCompactSize(s, vec.size());
        if (!vec.empty())
            s.write((char*)&vec[0], vec.size());
    }

    unsigned int GetSerializeSize(int, int = 0) const
    {
        return GetSizeOfCompactSize(vec.size()) + vec.size();
    }
};

template <size_t N, typename U>
LimitedVector<N, U> MakeLimitedVector(std::vector<U>& obj)
{
    return LimitedVector<N, U>(obj);
}

class Ack
{
public:
    std::vector<unsigned char> prefix;
    std::vector<unsigned char> preimage;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        uint64_t nPayload = 0;
        if (!ser_action.ForRead())
            nPayload = CalcPayloadSize(nType, nVersion);
        READWRITE(COMPACTSIZE(nPayload));
        if (nPayload == 0)
            throw std::runtime_error("Not valid ACK");
        READWRITE(LIMITED_VECTOR(prefix, 32));
        // Empty preimage should not be serialized
        if (ser_action.ForRead()) {
            uint64_t nPrefix = prefix.size();
            nPrefix += GetSizeOfCompactSize(nPrefix);
            if (nPayload > nPrefix)
                READWRITE(LIMITED_VECTOR(preimage, 32));
            if (CalcPayloadSize(nType, nVersion) != nPayload)
                throw std::runtime_error("Not valid ACK");
        } else {
            if (preimage.size() > 0)
                READWRITE(LIMITED_VECTOR(preimage, 32));
        }
    }

    unsigned int CalcPayloadSize(int nType, int nVersion) const
    {
        unsigned int nPayload = 0;
        nPayload += GetSizeOfCompactSize(prefix.size());
        nPayload += prefix.size();
        // Empty preimage should not be serialized
        if (!preimage.empty()) {
            nPayload += GetSizeOfCompactSize(preimage.size());
            nPayload += preimage.size();
        }
        return nPayload;
    }

    Ack() {}
    Ack(std::vector<unsigned char> prefix, std::vector<unsigned char> preimage = std::vector<unsigned char>())
        : prefix(prefix), preimage(preimage)
    {
    }
};

class AckList
{
public:
    std::vector<Ack> vAck;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        uint64_t sizePayload = 0;
        if (!ser_action.ForRead())
            sizePayload = CalcPayloadSize(nType, nVersion);
        READWRITE(COMPACTSIZE(sizePayload));
        if (ser_action.ForRead()) {
            unsigned int read = 0;
            while (read < sizePayload) {
                Ack ack;
                READWRITE(ack);
                read += ack.GetSerializeSize(nType, nVersion);
                vAck.push_back(ack);
            }
            if (read != sizePayload)
                throw std::runtime_error("Not valid ACK LIST");
        } else {
            for (Ack& ack : vAck) {
                READWRITE(ack);
            }
        }
    }

    unsigned int CalcPayloadSize(int nType, int nVersion) const
    {
        unsigned int nPayload = 0;
        for (const Ack& ack : vAck) {
            nPayload += ack.GetSerializeSize(nType, nVersion);
        }
        return nPayload;
    }

    AckList() {}
    AckList(std::vector<Ack> acks) : vAck(acks) {}
};

class ChainAckList
{
public:
    std::vector<unsigned char> chainId;
    AckList ackList;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        uint64_t nPayload = 0;
        if (!ser_action.ForRead())
            nPayload = CalcPayloadSize(nType, nVersion);
        READWRITE(COMPACTSIZE(nPayload));
        READWRITE(LIMITED_VECTOR(chainId, 20));
        READWRITE(ackList);
        if (ser_action.ForRead() && nPayload != CalcPayloadSize(nType, nVersion))
            throw std::runtime_error("Not valid CHAIN ACK LIST");
    }

    unsigned int CalcPayloadSize(int nType, int nVersion) const
    {
        unsigned int nPayload = 0;
        nPayload += GetSizeOfCompactSize(chainId.size());
        nPayload += chainId.size();
        nPayload += ackList.GetSerializeSize(nType, nVersion);
        return nPayload;
    }

    ChainAckList& operator<<(Ack ack)
    {
        ackList.vAck.push_back(ack);
        return *this;
    }

    ChainAckList() {}
    ChainAckList(std::vector<unsigned char> chainId) : chainId(chainId) {}
};

class FullAckList
{
public:
    std::vector<ChainAckList> vChainAcks;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        uint64_t sizePayload = 0;
        if (!ser_action.ForRead())
            sizePayload = CalcPayloadSize(nType, nVersion);
        READWRITE(COMPACTSIZE(sizePayload));
        if (ser_action.ForRead()) {
            uint64_t read = 0;
            while (read < sizePayload) {
                ChainAckList chainAcks;
                READWRITE(chainAcks);
                read += chainAcks.GetSerializeSize(nType, nVersion);
                vChainAcks.push_back(chainAcks);
            }
            if (read != sizePayload)
                throw std::runtime_error("Not valid FULL ACK LIST");
        } else {
            for (auto& chainAcks : vChainAcks) {
                READWRITE(chainAcks);
            }
        }
    }

    unsigned int CalcPayloadSize(int nType, int nVersion) const
    {
        unsigned int nPayloadSize = 0;
        for (const auto& chainAcks : vChainAcks) {
            nPayloadSize += chainAcks.GetSerializeSize(nType, nVersion);
        }
        return nPayloadSize;
    }

    FullAckList& operator<<(Ack ack)
    {
        if (!vChainAcks.empty()) {
            vChainAcks.rbegin()[0].ackList.vAck.push_back(ack);
        } else {
            throw std::runtime_error("Empty Chain");
        }
        return *this;
    }

    FullAckList& operator<<(ChainAckList chainAckList)
    {
        vChainAcks.push_back(chainAckList);
        return *this;
    }

    FullAckList() {}
};

class BaseBlockReader
{
public:
    virtual int GetBlockNumber() const
    {
        return -1;
    }

    virtual CTransaction GetBlockCoinbase(int blockNumber) const
    {
        return CTransaction();
    }
};

bool CountAcks(const std::vector<unsigned char> hashSpend, const std::vector<unsigned char>& chainId, int periodAck, int periodLiveness, int& positiveAcks, int& negativeAcks, const BaseBlockReader& blockReader);

#endif // BITCOIN_SCRIPT_DRIVECHAIN_H
