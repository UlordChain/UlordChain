// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test/test_bitcoin.h"

#include "chainparams.h"
#include "consensus/validation.h"
#include "crypto/sha256.h"
#include "keystore.h"
#include "main.h"
#include "miner.h"
#include "policy/policy.h"
#include "script/drivechain.h"
#include "script/interpreter.h"

#include <memory>
#include <boost/test/unit_test.hpp>

namespace
{
/* Test fixture */
class DriveChainSetup : public TestingSetup
{
public:
    std::vector<CTransaction> coinbaseTxns;

    CBlock CreateBlock(const std::vector<CMutableTransaction>& txns, const CScript& scriptPubKey);

    bool ProcessBlock(CBlock& block);

    DriveChainSetup();
};

DriveChainSetup::DriveChainSetup() : TestingSetup(CBaseChainParams::REGTEST)
{
}

CBlock DriveChainSetup::CreateBlock(const std::vector<CMutableTransaction>& txns, const CScript& scriptPubKey)
{
    const CChainParams& chainparams = Params();
    CBlockTemplate* pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
    CBlock* pblock = &pblocktemplate->block;

    pblock->vtx.resize(1);
    for (const CMutableTransaction& tx : txns)
        pblock->vtx.push_back(tx);

    CBlock block(*pblock);
    delete pblocktemplate;

    return block;
}

bool DriveChainSetup::ProcessBlock(CBlock& block)
{
    const CChainParams& chainparams = Params();

    unsigned int extraNonce = 0;
    IncrementExtraNonce(&block, chainActive.Tip(), extraNonce);

    while (!CheckProofOfWork(block.GetHash(), block.nBits, chainparams.GetConsensus()))
        ++block.nNonce;

    CValidationState state;
    bool result = ProcessNewBlock(state, chainparams, NULL, &block, true, NULL);

    coinbaseTxns.push_back(block.vtx[0]);

    return result;
}

/* To nicely convert from char* to vector<unsigned char> without '\0' at the end */
template <typename U, unsigned int N>
std::vector<unsigned char> ChainIdFromString(U(&in)[N])
{
    return std::vector<unsigned char>(in, in + N - 1); // Skip final '\0'
}

/* Create a transaction with a script vote */
CTransaction CreateTxVote(std::vector<unsigned char> script)
{
    CMutableTransaction tx;
    tx.vout.resize(1);
    tx.vout[0].scriptPubKey = CScript() << OP_RETURN << script;
    return tx;
}

/* Create transaction list with a script vote */
std::map<int, CTransaction> CreateTxVote(int from, int to, std::vector<unsigned char> script)
{
    std::map<int, CTransaction> result;
    for (int i = from; i <= to; ++i)
        result[i] = CreateTxVote(script);
    return result;
}

/* Returns a vector with the object t serialized */
template <typename T>
std::vector<unsigned char> SerializeDrivechain(T t, bool label = false)
{
    CDataStream dataStream(SER_DISK, 0);
    if (label)
        dataStream.write(reinterpret_cast<const char*>(&ACK_LABEL[0]), ACK_LABEL_LENGTH);
    dataStream << t;
    return std::vector<unsigned char>(dataStream.begin(), dataStream.end());
}

template <typename T>
T ParseDrivechain(const std::vector<unsigned char>& payload, uint* rest = nullptr)
{
    T t;
    CDataStream ss(payload, SER_DISK, 0);
    ss >> t;
    if (rest)
        *rest = ss.size();
    return t;
}

/* Blockchain mock for VerifyScript and EvalScript */
class DriveChainTestCheckerBlockReader : public TransactionSignatureChecker, public BaseBlockReader
{
    int blockNumber;
    std::vector<unsigned char> hashSpend;
    std::map<int, CTransaction> txs;
    const CTransaction txTo;

public:
    bool CheckSig(const std::vector<unsigned char>& vchSigIn, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const
    {
        return true;
    }

    virtual bool CountAcks(const std::vector<unsigned char>& chainId, int periodAck, int periodLiveness, int& positiveAcks, int& negativeAcks) const
    {
        return ::CountAcks(hashSpend, chainId, periodAck, periodLiveness, positiveAcks, negativeAcks, *this);
    }

    virtual int GetBlockNumber() const
    {
        return blockNumber;
    }

    virtual CTransaction GetBlockCoinbase(int blockNumber) const
    {
        auto result = txs.find(blockNumber);
        if (result != txs.end()) {
            return (*result).second;
        }
        return CTransaction();
    }

    DriveChainTestCheckerBlockReader(int blockNumber, const std::vector<unsigned char>& hashSpend, const std::map<int, CTransaction>& txs, const CAmount& amount)
        : TransactionSignatureChecker(&txTo, 0, amount), blockNumber(blockNumber), hashSpend(hashSpend), txs(txs)
    {
    }
};

/* Like CHashWriter but only applies SHA256 once */
class SHA256Writer
{
private:
    CSHA256 ctx;

public:
    int nType;
    int nVersion;

    SHA256Writer(int nTypeIn, int nVersionIn) : nType(nTypeIn), nVersion(nVersionIn) {}

    SHA256Writer& write(const char* pch, size_t size)
    {
        ctx.Write((const unsigned char*)pch, size);
        return (*this);
    }

    uint256 GetHash()
    {
        uint256 result;
        ctx.Finalize((unsigned char*)&result);
        return result;
    }

    template <typename T>
    SHA256Writer& operator<<(const T& obj)
    {
        ::Serialize(*this, obj, nType, nVersion);
        return (*this);
    }
};

// Helper to concatenate two maps
template <typename M1, typename M2>
void InsertMap(M1& m1, const M2& m2)
{
    m1.insert(m2.cbegin(), m2.cend());
}

// Evaluate a call to EvalScript
void RunEvalScriptTest(std::vector<unsigned char> hash, std::map<int, CTransaction> txs, CScript scriptPubKey, int blockNumber, ScriptError result, int positive = -1, int negative = -1)
{
    DriveChainTestCheckerBlockReader checker(blockNumber, hash, txs, 1);
    std::vector<std::vector<unsigned char> > stack;
    ScriptError err;
    BOOST_CHECK(EvalScript(stack, scriptPubKey, STANDARD_SCRIPT_VERIFY_FLAGS, checker, SIGVERSION_WITNESS_V1, &err) == (result == SCRIPT_ERR_OK));
    BOOST_CHECK(err == result);
    if (result == SCRIPT_ERR_OK) {
        BOOST_CHECK(stack.size() == 2);
        CScriptNum positiveAcks(stack[0], true);
        CScriptNum negativeAcks(stack[1], true);
        BOOST_CHECK(positiveAcks.getint() == positive);
        BOOST_CHECK(negativeAcks.getint() == negative);
    }
}

// Evaluate a call to VerifyScript
void RunVerifyScriptTest(std::vector<unsigned char> hash, std::map<int, CTransaction> txs, CScript witscript, int blockNumber, ScriptError result)
{
    CScript scriptPubKey;
    {
        uint256 hash;
        int witnessversion = 0;
        CSHA256().Write(&witscript[0], witscript.size()).Finalize(hash.begin());
        scriptPubKey = CScript() << witnessversion << ToByteVector(hash);
    }

    CScriptWitness scriptWitness;
    scriptWitness.stack.push_back(std::vector<unsigned char>(witscript.begin(), witscript.end()));

    DriveChainTestCheckerBlockReader checker(blockNumber, hash, txs, 1);

    ScriptError err;
    BOOST_CHECK(::VerifyScript(CScript(), scriptPubKey, &scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, checker, &err) == (result == SCRIPT_ERR_OK));
}
}

BOOST_FIXTURE_TEST_SUITE(drivechain_tests, DriveChainSetup)

BOOST_AUTO_TEST_CASE(ParsingTest)
{
    {
        Ack ack;
        BOOST_CHECK_NO_THROW(ack = ParseDrivechain<Ack>(ParseHex("0100")));
        BOOST_CHECK(ack.prefix.size() == 0);
        BOOST_CHECK(ack.preimage.size() == 0);
    }
    {
        Ack ack;
        BOOST_CHECK_NO_THROW(ack = ParseDrivechain<Ack>(ParseHex("010000"))); // 1 extra byte after payload
        BOOST_CHECK(ack.prefix.size() == 0);
        BOOST_CHECK(ack.preimage.size() == 0);
    }
    {
        Ack ack;
        BOOST_CHECK_NO_THROW(ack = ParseDrivechain<Ack>(ParseHex("0201BA")));
        BOOST_CHECK(ack.prefix.size() == 1);
        BOOST_CHECK(ack.prefix == ParseHex("BA"));
        BOOST_CHECK(ack.preimage.size() == 0);
    }
    {
        Ack ack;
        BOOST_CHECK_NO_THROW(ack = ParseDrivechain<Ack>(ParseHex("0201DEFB")));
        BOOST_CHECK(ack.prefix.size() == 1);
        BOOST_CHECK(ack.prefix == ParseHex("DE"));
        BOOST_CHECK(ack.preimage.size() == 0);
    }
    {
        //0x04014E018F:
        //0x04: 后面的有用字节的长度
        //0x01: prefix长度为1字节
        //0x4e: prefix 正文
        //0x01: preimg 长度
        //0x8f: preimg 正文
        Ack ack;
        BOOST_CHECK_NO_THROW(ack = ParseDrivechain<Ack>(ParseHex("04014E018F")));
        BOOST_CHECK(ack.prefix.size() == 1);
        BOOST_CHECK(ack.prefix == ParseHex("4E"));
        BOOST_CHECK(ack.preimage.size() == 1);
        BOOST_CHECK(ack.preimage == ParseHex("8F"));
    }
    {
        Ack ack;
        BOOST_CHECK_NO_THROW(ack = ParseDrivechain<Ack>(ParseHex("03000136")));
        BOOST_CHECK(ack.prefix.size() == 0);
        BOOST_CHECK(ack.preimage.size() == 1);
        BOOST_CHECK(ack.preimage == ParseHex("36"));
    }
    {
        Ack ack;
        BOOST_CHECK_NO_THROW(ack = ParseDrivechain<Ack>(ParseHex("2120000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")));
        BOOST_CHECK(ack.prefix.size() == 32);
        BOOST_CHECK(ack.prefix == ParseHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"));
        BOOST_CHECK(ack.preimage.size() == 0);
    }
    {
        Ack ack;
        BOOST_CHECK_NO_THROW(ack = ParseDrivechain<Ack>(ParseHex("4220000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
                                                                 "20000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")));
        BOOST_CHECK(ack.prefix.size() == 32);
        BOOST_CHECK(ack.prefix == ParseHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"));
        BOOST_CHECK(ack.preimage.size() == 32);
        BOOST_CHECK(ack.preimage == ParseHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"));
    }
    BOOST_CHECK_THROW(ParseDrivechain<Ack>(ParseHex("00")), std::runtime_error);                                                                     // Bad payload size
    BOOST_CHECK_THROW(ParseDrivechain<Ack>(ParseHex("01")), std::runtime_error);                                                                     // Missing payload
    BOOST_CHECK_THROW(ParseDrivechain<Ack>(ParseHex("0101")), std::runtime_error);                                                                   // Broken payload
    BOOST_CHECK_THROW(ParseDrivechain<Ack>(ParseHex("010100")), std::runtime_error);                                                                 // Incorrect payload size
    BOOST_CHECK_THROW(ParseDrivechain<Ack>(ParseHex("01010000")), std::runtime_error);                                                               // Incorrect payload: size mismatch
    BOOST_CHECK_THROW(ParseDrivechain<Ack>(ParseHex("03010000")), std::runtime_error);                                                               // Incorrect payload: empty preimage
    BOOST_CHECK_THROW(ParseDrivechain<Ack>(ParseHex("2221000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20")), std::runtime_error); // hash and preimage are 32 bytes or less

    {
        AckList ackList;
        BOOST_CHECK_NO_THROW(ackList = ParseDrivechain<AckList>(ParseHex("00")));
        BOOST_CHECK(ackList.vAck.size() == 0);
    }
    {
        AckList ackList;
        BOOST_CHECK_NO_THROW(ackList = ParseDrivechain<AckList>(ParseHex("020100")));
        BOOST_CHECK(ackList.vAck.size() == 1);
        BOOST_CHECK(ackList.vAck[0].prefix.size() == 0);
    }
    {
        AckList ackList;
        BOOST_CHECK_NO_THROW(ackList = ParseDrivechain<AckList>(ParseHex("030201C7")));
        BOOST_CHECK(ackList.vAck.size() == 1);
        BOOST_CHECK(ackList.vAck[0].prefix.size() == 1);
        BOOST_CHECK(ackList.vAck[0].prefix == ParseHex("C7"));
    }
    {
        AckList ackList;
        BOOST_CHECK_NO_THROW(ackList = ParseDrivechain<AckList>(ParseHex("030201C0020100")));
        BOOST_CHECK(ackList.vAck.size() == 1);
        BOOST_CHECK(ackList.vAck[0].prefix.size() == 1);
        BOOST_CHECK(ackList.vAck[0].prefix == ParseHex("C0"));
    }
    {
        AckList ackList;
        BOOST_CHECK_NO_THROW(ackList = ParseDrivechain<AckList>(ParseHex("0401000100")));
        BOOST_CHECK(ackList.vAck.size() == 2);
        BOOST_CHECK(ackList.vAck[0].prefix.size() == 0);
        BOOST_CHECK(ackList.vAck[0].preimage.size() == 0);
        BOOST_CHECK(ackList.vAck[1].prefix.size() == 0);
        BOOST_CHECK(ackList.vAck[1].preimage.size() == 0);
    }
    BOOST_CHECK_THROW(ParseDrivechain<AckList>(ParseHex("0100")), std::runtime_error);
    BOOST_CHECK_THROW(ParseDrivechain<AckList>(ParseHex("0501000100")), std::runtime_error);
    BOOST_CHECK_THROW(ParseDrivechain<AckList>(ParseHex("05010001000100")), std::runtime_error);

    {
        ChainAckList chainAckList;
        BOOST_CHECK_NO_THROW(chainAckList = ParseDrivechain<ChainAckList>(ParseHex("0301FF00")));
        BOOST_CHECK(chainAckList.chainId.size() == 1);
        BOOST_CHECK(chainAckList.chainId == ParseHex("FF"));
        BOOST_CHECK(chainAckList.ackList.vAck.size() == 0);
    }
    {
        ChainAckList chainAckList;
        BOOST_CHECK_NO_THROW(chainAckList = ParseDrivechain<ChainAckList>(ParseHex("0501CA020100")));
        BOOST_CHECK(chainAckList.chainId.size() == 1);
        BOOST_CHECK(chainAckList.chainId == ParseHex("CA"));
        BOOST_CHECK(chainAckList.ackList.vAck.size() == 1);
        BOOST_CHECK(chainAckList.ackList.vAck[0].prefix.size() == 0);
        BOOST_CHECK(chainAckList.ackList.vAck[0].preimage.size() == 0);
    }
    {
        ChainAckList chainAckList;
        BOOST_CHECK_NO_THROW(chainAckList = ParseDrivechain<ChainAckList>(ParseHex("1614000102030405060708090A0B0C0D0E0F1011121300")));
        BOOST_CHECK(chainAckList.chainId.size() == 20);
        BOOST_CHECK(chainAckList.chainId == ParseHex("000102030405060708090A0B0C0D0E0F10111213"));
        BOOST_CHECK(chainAckList.ackList.vAck.size() == 0);
    }
    {
        ChainAckList chainAckList;
        BOOST_CHECK_NO_THROW(chainAckList = ParseDrivechain<ChainAckList>(ParseHex("FDFF000158FC"
                                                                                   "0100010001000100010001000100010001000100010001000100010001000100"
                                                                                   "0100010001000100010001000100010001000100010001000100010001000100"
                                                                                   "0100010001000100010001000100010001000100010001000100010001000100"
                                                                                   "0100010001000100010001000100010001000100010001000100010001000100"
                                                                                   "0100010001000100010001000100010001000100010001000100010001000100"
                                                                                   "0100010001000100010001000100010001000100010001000100010001000100"
                                                                                   "0100010001000100010001000100010001000100010001000100010001000100"
                                                                                   "01000100010001000100010001000100010001000100010001000100")));
        BOOST_CHECK(chainAckList.chainId.size() == 1);
        BOOST_CHECK(chainAckList.chainId == ParseHex("58"));
        BOOST_CHECK(chainAckList.ackList.vAck.size() == 126);
        for (int i = 0; i < 126; ++i) {
            BOOST_CHECK(chainAckList.ackList.vAck[i].prefix.size() == 0);
            BOOST_CHECK(chainAckList.ackList.vAck[i].preimage.size() == 0);
        }
    }
    BOOST_CHECK_THROW(ParseDrivechain<ChainAckList>(ParseHex("171500000000000000000000000000000000000000000000")), std::runtime_error);
    BOOST_CHECK_THROW(ParseDrivechain<ChainAckList>(ParseHex("0502FF")), std::runtime_error);
    BOOST_CHECK_THROW(ParseDrivechain<ChainAckList>(ParseHex("FD000301FF00")), std::runtime_error);
    BOOST_CHECK_THROW(ParseDrivechain<ChainAckList>(ParseHex("0502FF")), std::runtime_error);
}
/*

BOOST_AUTO_TEST_CASE(SerializingTest)
{
    {
        BOOST_CHECK(SerializeDrivechain(Ack()) == ParseHex("0100"));
        BOOST_CHECK(SerializeDrivechain(Ack(ParseHex("BA"))) == ParseHex("0201BA"));
        BOOST_CHECK(SerializeDrivechain(Ack(ParseHex(""), ParseHex("BA"))) == ParseHex("030001BA"));
        BOOST_CHECK(SerializeDrivechain(Ack(ParseHex("BA"), ParseHex("BA"))) == ParseHex("0401BA01BA"));
    }
    {
        BOOST_CHECK(SerializeDrivechain(ChainAckList(ChainIdFromString("X")) << Ack()) == ParseHex("050158020100"));
        BOOST_CHECK(SerializeDrivechain(ChainAckList(ChainIdFromString("X")) << Ack(ParseHex("ABCD"), ParseHex(""))) == ParseHex("070158040302ABCD"));
        BOOST_CHECK(SerializeDrivechain(ChainAckList(ChainIdFromString("X")) << Ack(ParseHex(""), ParseHex("ABCD"))) == ParseHex("08015805040002ABCD"));
        BOOST_CHECK(SerializeDrivechain(ChainAckList(ChainIdFromString("Y")) << Ack() << Ack()) == ParseHex("0701590401000100"));
        BOOST_CHECK(SerializeDrivechain(ChainAckList(ChainIdFromString("Y")) << Ack(ParseHex("10")) << Ack(ParseHex(""), ParseHex("10"))) ==
                    ParseHex("0A01590702011003000110"));
        BOOST_CHECK(SerializeDrivechain(ChainAckList(ChainIdFromString("X")) << Ack(ParseHex("10")) << Ack(ParseHex("20"))) ==
                    ParseHex("09015806020110020120"));
        BOOST_CHECK(SerializeDrivechain(ChainAckList(ChainIdFromString("Y")) << Ack(ParseHex("BA")) << Ack(ParseHex("BA"))) ==
                    ParseHex("090159060201BA0201BA"));
    }
    {
        BOOST_CHECK(SerializeDrivechain(
                        FullAckList() << ChainAckList(ChainIdFromString("X")) << Ack(ParseHex("DE")) << Ack(ParseHex("BA"))
                                      << ChainAckList(ChainIdFromString("Y")) << Ack(ParseHex("0102")) << Ack(ParseHex(""))) ==
                    ParseHex("14090158060201DE0201BA09015906030201020100"));
    }
    {
        std::vector<unsigned char> payload = SerializeDrivechain(
            FullAckList() << ChainAckList(ChainIdFromString("DRVCOIN")) << Ack(ParseHex(""), ParseHex("00102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F0")));
        BOOST_CHECK(payload == ParseHex("2D2C07445256434F494E2322002000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F0"));
    }
}

BOOST_AUTO_TEST_CASE(EvalScriptTest)
{
    const auto preimage = ParseHex("1010101010101010101010101010101010101010101010101010101010101010");
    const auto hash = ParseHex("baa501b37267c06d8d20f316622f90a3e343e9e730771f2ce2e314b794e31853");
    const CScript scriptPubKey = CScript() << ChainIdFromString("XCOIN") << CScriptNum(144) << CScriptNum(144) << OP_COUNT_ACKS;

    {
        // Invalid block number
        RunEvalScriptTest(hash, std::map<int, CTransaction>(), scriptPubKey, 200, SCRIPT_ERR_COUNT_ACKS_INVALID_PARAM);
    }
    {
        std::map<int, CTransaction> txs;
        InsertMap(txs, CreateTxVote(101, 101, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex(""), preimage), true)));
        InsertMap(txs, CreateTxVote(102, 125, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex("ba")), true)));
        InsertMap(txs, CreateTxVote(201, 225, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(), true)));
        RunEvalScriptTest(hash, txs, scriptPubKey, 370, SCRIPT_ERR_OK, 25, 25);
    }
    {
        // Incorrect hash
        auto hash = ParseHex("baD501b37267c06d8d20f316622f90a3e343e9e730771f2ce2e314b794e31853");

        std::map<int, CTransaction> txs;
        InsertMap(txs, CreateTxVote(101, 101, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex(""), preimage), true)));
        InsertMap(txs, CreateTxVote(102, 125, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex("ba")), true)));
        InsertMap(txs, CreateTxVote(201, 225, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(), true)));

        RunEvalScriptTest(hash, std::map<int, CTransaction>(), scriptPubKey, 370, SCRIPT_ERR_COUNT_ACKS_INVALID_PARAM);
    }
    {
        std::map<int, CTransaction> txs;
        InsertMap(txs, CreateTxVote(101, 101, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex(""), preimage), true)));
        InsertMap(txs, CreateTxVote(102, 200, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex("ba")), true)));
        InsertMap(txs, CreateTxVote(201, 225, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(), true)));

        RunEvalScriptTest(hash, txs, scriptPubKey, 370, SCRIPT_ERR_OK, 100, 25);
    }
}

BOOST_AUTO_TEST_CASE(VerifyScriptTest)
{
    const auto preimage = ParseHex("1010101010101010101010101010101010101010101010101010101010101010");
    const auto hash = ParseHex("baa501b37267c06d8d20f316622f90a3e343e9e730771f2ce2e314b794e31853");

    CScript witscript = CScript()
                        << ChainIdFromString("XCOIN")
                        << CScriptNum(144)
                        << CScriptNum(144)
                        << OP_COUNT_ACKS
                        << OP_2DUP
                        << OP_GREATERTHAN
                        << OP_VERIFY
                        << OP_SUB
                        << CScriptNum(72)
                        << OP_GREATERTHAN;

    {
        // Invalid block number
        RunVerifyScriptTest(hash, std::map<int, CTransaction>(), witscript, 250, SCRIPT_ERR_COUNT_ACKS_INVALID_PARAM);
    }

    {
        // Not enough positive votes
        std::map<int, CTransaction> txs;
        InsertMap(txs, CreateTxVote(101, 101, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex(""), preimage), true)));
        InsertMap(txs, CreateTxVote(102, 172, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex("ab")), true)));
        InsertMap(txs, CreateTxVote(201, 225, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(), true)));

        RunVerifyScriptTest(hash, txs, witscript, 370, SCRIPT_ERR_COUNT_ACKS_INVALID_PARAM);
    }

    {
        // Not valid votes
        std::map<int, CTransaction> txs;
        InsertMap(txs, CreateTxVote(101, 101, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex(""), preimage), true)));
        InsertMap(txs, CreateTxVote(102, 200, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex("ab")), true)));
        InsertMap(txs, CreateTxVote(201, 225, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(), true)));

        RunVerifyScriptTest(hash, txs, witscript, 370, SCRIPT_ERR_COUNT_ACKS_INVALID_PARAM);
    }

    {
        std::map<int, CTransaction> txs;
        InsertMap(txs, CreateTxVote(101, 101, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex(""), preimage), true)));
        InsertMap(txs, CreateTxVote(102, 200, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex("ba")), true)));
        InsertMap(txs, CreateTxVote(201, 225, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(), true)));

        RunVerifyScriptTest(hash, txs, witscript, 370, SCRIPT_ERR_OK);
    }

    {
        // Prefix can have any size
        std::map<int, CTransaction> txs;
        InsertMap(txs, CreateTxVote(101, 101, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex(""), preimage), true)));
        InsertMap(txs, CreateTxVote(102, 119, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex("baa5")), true)));
        InsertMap(txs, CreateTxVote(120, 200, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex("ba")), true)));
        InsertMap(txs, CreateTxVote(201, 225, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(), true)));
        InsertMap(txs, CreateTxVote(230, 300, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex("fe")), true)));

        RunVerifyScriptTest(hash, txs, witscript, 370, SCRIPT_ERR_OK);
    }

    {
        // Ignore invalid votes
        std::map<int, CTransaction> txs;
        InsertMap(txs, CreateTxVote(101, 101, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex(""), preimage), true)));
        InsertMap(txs, CreateTxVote(102, 119, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex(""), ParseHex("de")) << Ack(ParseHex("baa5")), true)));
        InsertMap(txs, CreateTxVote(120, 200, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex("ba")), true)));
        InsertMap(txs, CreateTxVote(201, 225, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(), true)));
        InsertMap(txs, CreateTxVote(230, 300, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex("fe")), true)));

        RunVerifyScriptTest(hash, txs, witscript, 370, SCRIPT_ERR_OK);
    }

    {
        // Different coin tag
        std::map<int, CTransaction> txs;
        InsertMap(txs, CreateTxVote(101, 101, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("YCOIN")) << Ack(ParseHex(""), preimage), true)));
        InsertMap(txs, CreateTxVote(102, 200, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("YCOIN")) << Ack(ParseHex("ba")), true)));
        InsertMap(txs, CreateTxVote(201, 225, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("YCOIN")) << Ack(), true)));

        RunVerifyScriptTest(hash, txs, witscript, 370, SCRIPT_ERR_COUNT_ACKS_INVALID_PARAM);
    }

    {
        // Accept non-empty hash when sha256(preimage) == hash
        std::map<int, CTransaction> txs;
        InsertMap(txs, CreateTxVote(101, 101, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(hash, preimage), true)));
        InsertMap(txs, CreateTxVote(102, 200, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex("ba")), true)));
        InsertMap(txs, CreateTxVote(201, 225, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(), true)));

        RunVerifyScriptTest(hash, txs, witscript, 370, SCRIPT_ERR_OK);
    }

    {
        // Invalid proposal when sha256(preimage) != hash
        auto preimage = ParseHex("2020202020202020202020202020202020202020202020202020202020202020");
        std::map<int, CTransaction> txs;
        InsertMap(txs, CreateTxVote(101, 101, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("YCOIN")) << Ack(hash, preimage), true)));
        InsertMap(txs, CreateTxVote(102, 200, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("YCOIN")) << Ack(ParseHex("ba")), true)));
        InsertMap(txs, CreateTxVote(201, 225, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("YCOIN")) << Ack(), true)));

        RunVerifyScriptTest(hash, txs, witscript, 370, SCRIPT_ERR_COUNT_ACKS_INVALID_PARAM);
    }

    {
        // Ignore other coins votes
        std::map<int, CTransaction> txs;
        InsertMap(txs, CreateTxVote(101, 101, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex(""), preimage), true)));
        InsertMap(txs, CreateTxVote(102, 200, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex("ba")) << ChainAckList(ChainIdFromString("YCOIN")) << Ack(ParseHex("baa5")), true)));
        InsertMap(txs, CreateTxVote(201, 225, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("YCOIN")) << Ack(ParseHex("ba")) << ChainAckList(ChainIdFromString("XCOIN")) << Ack(), true)));

        RunVerifyScriptTest(hash, txs, witscript, 370, SCRIPT_ERR_OK);
    }
}

BOOST_AUTO_TEST_CASE(BlockchainTest)
{
    CScript scriptPubKey;
    CScript witscript;
    CScriptWitness scriptWitness;

    witscript = CScript() << ChainIdFromString("XCOIN")
                          << CScriptNum(144)
                          << CScriptNum(144)
                          << OP_COUNT_ACKS
                          << OP_2DUP
                          << OP_GREATERTHAN
                          << OP_VERIFY
                          << OP_SUB
                          << CScriptNum(72)
                          << OP_GREATERTHAN;

    const int BLOCK_BASE = 70; // Seems witness is not activated before block 431

    {
        uint256 hash;
        int witnessversion = 0;
        CSHA256().Write(&witscript[0], witscript.size()).Finalize(hash.begin());
        scriptPubKey = CScript() << witnessversion << ToByteVector(hash);
    }

    for (int i = 1; i <= 100 + BLOCK_BASE; ++i) {
        CBlock block = CreateBlock(std::vector<CMutableTransaction>(), scriptPubKey);
        BOOST_CHECK(ProcessBlock(block));
        BOOST_CHECK(chainActive.Height() == i);
    }

    CMutableTransaction spendTx;
    {
        spendTx.nVersion = 1;
        spendTx.nLockTime = 0;
        spendTx.vin.resize(1);
        spendTx.vout.resize(1);
        spendTx.wit.vtxinwit.resize(1);
        spendTx.wit.vtxinwit[0].scriptWitness = CScriptWitness();
        spendTx.vin[0].prevout.hash = coinbaseTxns[0].GetHash();
        spendTx.vin[0].prevout.n = 0;
        spendTx.vin[0].scriptSig = CScript();
        spendTx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
        spendTx.vout[0].scriptPubKey = CScript();
        spendTx.vout[0].nValue = coinbaseTxns[0].vout[0].nValue;
    }

    scriptWitness.stack.push_back(std::vector<unsigned char>(witscript.begin(), witscript.end()));
    spendTx.wit.vtxinwit[0].scriptWitness = scriptWitness;

    uint256 preimage;
    uint256 hashSpend;

    {
        SHA256Writer ss(SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
        ss << spendTx;
        preimage = ss.GetHash();
        CSHA256().Write(preimage.begin(), preimage.size()).Finalize(hashSpend.begin());
        BOOST_CHECK(hashSpend == spendTx.GetHash());
    }

    {
        std::vector<unsigned char> proposal = SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ChainIdFromString(""), std::vector<unsigned char>(preimage.begin(), preimage.end())), true);

        CBlock block = CreateBlock(std::vector<CMutableTransaction>(), scriptPubKey);
        CMutableTransaction coinbase(block.vtx[0]);
        coinbase.vout.resize(2);
        coinbase.vout[1].nValue = 0;
        coinbase.vout[1].scriptPubKey = CScript() << OP_RETURN << proposal;
        block.vtx[0] = coinbase;
        BOOST_CHECK(ProcessBlock(block));
        BOOST_CHECK(chainActive.Height() == 101 + BLOCK_BASE);
    }


    {
        std::vector<unsigned char> positiveVote = SerializeDrivechain(
            FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(std::vector<unsigned char>(hashSpend.begin(), hashSpend.begin() + 1)), true);
        for (unsigned int i = 102 + BLOCK_BASE; i <= 200 + BLOCK_BASE; ++i) {
            CBlock block = CreateBlock(std::vector<CMutableTransaction>(), scriptPubKey);
            CMutableTransaction coinbase(block.vtx[0]);
            coinbase.vout.resize(2);
            coinbase.vout[1].nValue = CAmount(0);
            coinbase.vout[1].scriptPubKey = CScript() << OP_RETURN << positiveVote;
            block.vtx[0] = coinbase;
            BOOST_CHECK(ProcessBlock(block));
            BOOST_CHECK_EQUAL(chainActive.Height(), i);
        }
    }

    {
        std::vector<unsigned char> negativeVote = SerializeDrivechain(
            FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(), true);
        for (unsigned int i = 201 + BLOCK_BASE; i <= 225 + BLOCK_BASE; ++i) {
            CBlock block = CreateBlock(std::vector<CMutableTransaction>(), scriptPubKey);
            CMutableTransaction coinbase(block.vtx[0]);
            coinbase.vout.resize(2);
            coinbase.vout[1].nValue = CAmount(0);
            coinbase.vout[1].scriptPubKey = CScript() << OP_RETURN << negativeVote;
            block.vtx[0] = coinbase;
            BOOST_CHECK(ProcessBlock(block));
            BOOST_CHECK_EQUAL(chainActive.Height(), i);
        }
    }

    {
        for (unsigned int i = 226 + BLOCK_BASE; i <= 369 + BLOCK_BASE; ++i) {
            CBlock block = CreateBlock(std::vector<CMutableTransaction>(), scriptPubKey);
            BOOST_CHECK(ProcessBlock(block));
            BOOST_CHECK_EQUAL(chainActive.Height(), i);
        }
    }

    {
        const CChainParams& chainparams = Params();
        CBlock block = CreateBlock(std::vector<CMutableTransaction>{spendTx}, scriptPubKey);
        GenerateCoinbaseCommitment(block, chainActive.Tip(), chainparams.GetConsensus());
        BOOST_CHECK(ProcessBlock(block));
        BOOST_CHECK(chainActive.Height() == 370 + BLOCK_BASE);
    }
}  

*/

BOOST_AUTO_TEST_SUITE_END()
