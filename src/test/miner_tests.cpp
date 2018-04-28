// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "coins.h"
#include "consensus/consensus.h"
#include "consensus/merkle.h"
#include "consensus/validation.h"
#include "main.h"
#include "masternode-payments.h"
#include "miner.h"
#include "pubkey.h"
#include "script/standard.h"
#include "txmempool.h"
#include "uint256.h"
#include "util.h"
#include "utilstrencodings.h"
#include <string>

#include "test/test_ulord.h"

#include <boost/test/unit_test.hpp>
using namespace std;
BOOST_FIXTURE_TEST_SUITE(miner_tests, TestingSetup)
CScript COINBASE_FLAGS;

static
struct {
    unsigned int extranonce;
    string nonce;
	uint32_t time;
	string merkle;
} blockinfo[] = {
    {0, "000078f9660587d07127ae904619bd9f35837512a1c779a69ee55e57c6be037f",1524705988,"37ff3b65e89e8fe45feb9ebff7549b5250f0c43ba6a276392899c2f6522f9fce"},
    {0, "0000aa08ad525b620ecf58099020a0d63659ed374415c2360e28c9ec1c580414",1524705988,"40eda1e1235546a2e0afa58263c1f8adb6bd57c77406f845b79ea722933a31e6"}, 
    {0, "0000472398a8177b89ceee2518b976ee5a388eac1391fcfc0c6a706397090530",1524705988,"69ee517111ff32737f75f77c1a5a58b3a96a7fb4054fc91bf1ba7318b88a9c72"}, 
    {0, "00009ae3cebca826e8f67d4900bc8aab87bff15a7d02dd92fb2c7625040e0860",1524705988,"75c42159ad436a961b6054ab95256c46659c1e01c458865b19a65edc34d90b30"},
    
    {0, "00008e3f90b367bf07f963e5fd6b25545598f0eb330db1178aa2bfae06770382",1524705988,"e986d9d6b585888214b722c2f4aa4dd2ca58db4b332a4615f7b4c2a7f8b2c8f5"},
    {0, "0000560995e8cb482cc9bae546dd63e8100f00950ff2ebe9c1bc946b4dac00cd",1524705988,"92cfdb28b6536fae1feb50214b1a6e0c82234e7445304848d175219ff0f46464"},
    {0, "0000cc597012cbcfa8af68f773ea4d44729e7f7b7ed59746fd4b1a7dfc14014c",1524705988,"fff97fc22c2d9e41307aed3501e4744003ab35fc62d6db3a9aef664b580eb95f"},
    {0, "00009d1f1735a5c8f11b0ef6b292fe9d1beef4cb9b336770419dc78a2b520344",1524705988,"f7ae96de5a9101405a8267454af0d5d450664d0b11baa6b0b2d6c10a35c2bf47"},
    
    {0, "0000f728026c79abcd1e5a6cd96e43def56f43a83f29b96ddd0520ea3fc900c1",1524705988,"06de88fabac5d13cab314cc03d42db4090d57d59a304e9e9d95b8f765f034307"},
    {0, "0000f749cbdc97e21d3a1553a3d79fe2d2be15731a8e1dec478c494d727c0646",1524705988,"aed0923c148e0c59f81822b3ab0a98ce9714b2fa55c06eb208f8078d57d39b86"},
    {0, "0000b2808203ec95394b9fc3310a7414c6597411edbef12477c7316db1000688",1524705988,"3d555b4318480e276e7d01446e567333f7653458340266be934b7eada5960b5e"},
    {0, "0000c0f174abe3f41a7259af7fb124e54b67cfb7fbf7c115e1f6bcecc22f0b76",1524705988,"88df5cc7bc1eeeaba50a2ae0f510542730412ffb4dc1411580a550cf1d9d4f4f"},
};

CBlockIndex CreateBlockIndex(int nHeight)
{
    CBlockIndex index;
    index.nHeight = nHeight;
    index.pprev = chainActive.Tip();
    return index;
}

bool TestSequenceLocks(const CTransaction &tx, int flags)
{
    LOCK(mempool.cs);
    return CheckSequenceLocks(tx, flags);
}

// NOTE: These tests rely on CreateNewBlock doing its own self-validation!
BOOST_AUTO_TEST_CASE(CreateNewBlock_validity)
{
    const CChainParams& chainparams = Params(CBaseChainParams::TESTNET);
    CScript scriptPubKey = CScript() << ParseHex("034c73d75f59061a08032b68369e5034390abc5215b3df79be01fb4319173a88f8") << OP_CHECKSIG;
    CBlockTemplate *pblocktemplate;
    CMutableTransaction tx,tx2;
    CScript script;
    uint256 hash;
    TestMemPoolEntryHelper entry;
    entry.nFee = 11;
    entry.dPriority = 111.0;
    entry.nHeight = 11;

    LOCK(cs_main);
    fCheckpointsEnabled = false;

    // force UpdatedBlockTip to initialize pCurrentBlockIndex
    mnpayments.UpdatedBlockTip(chainActive.Tip());

    // Simple block creation, nothing special yet:
    BOOST_CHECK(pblocktemplate = CreateNewBlock(chainparams, scriptPubKey));

    // We can't make transactions until we have inputs
    // Therefore, load 100 blocks :)
    //int baseheight = 0;
    std::vector<CTransaction*>txFirst;
    for (unsigned int i = 0; i < sizeof(blockinfo)/sizeof(*blockinfo); ++i)
    {
        CBlock *pblock = &pblocktemplate->block; // pointer for convenience
        //pblock->nVersion = 1;
        //pblock->nTime = chainActive.Tip()->GetMedianTimePast()+1;
        CMutableTransaction txCoinbase(pblock->vtx[0]);
        txCoinbase.nVersion = 1;
        txCoinbase.vin[0].scriptSig = CScript();
        txCoinbase.vin[0].scriptSig.push_back(blockinfo[i].extranonce);
        txCoinbase.vin[0].scriptSig.push_back(chainActive.Height());
        txCoinbase.vout[0].scriptPubKey = CScript();
        pblock->vtx[0] = CTransaction(txCoinbase);
        //if (txFirst.size() == 0)
            //baseheight = chainActive.Height();
        if (txFirst.size() < 4)
            txFirst.push_back(new CTransaction(pblock->vtx[0]));
    //    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
		uint256 temp_nNonce;
		temp_nNonce.SetHex(blockinfo[i].nonce);
        pblock->nNonce = temp_nNonce;
		pblock->nTime = blockinfo[i].time;
		uint256 temp_mekle;
		temp_mekle.SetHex(blockinfo[i].merkle);
		pblock->hashMerkleRoot = temp_mekle;
        CValidationState state;
        //BOOST_CHECK(ProcessNewBlock(state, chainparams, NULL, pblock, true, NULL));
        //BOOST_CHECK(state.IsValid());
        ProcessNewBlock(state, chainparams, NULL, pblock, true, NULL);
        pblock->hashPrevBlock = pblock->GetHash();
    }
    delete pblocktemplate;

    // Just to make sure we can still make simple blocks
    BOOST_CHECK(pblocktemplate = CreateNewBlock(chainparams, scriptPubKey));
    delete pblocktemplate;
 
    // block sigops > limit: 1000 CHECKMULTISIG + 1
    tx.vin.resize(1);
    // NOTE: OP_NOP is used to force 20 SigOps for the CHECKMULTISIG
    tx.vin[0].scriptSig = CScript() << OP_0 << OP_0 << OP_0 << OP_NOP << OP_CHECKMULTISIG << OP_1;
    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vin[0].prevout.n = 0;
    tx.vout.resize(1);
    tx.vout[0].nValue = 50000000000LL;
    for (unsigned int i = 0; i < 1001; ++i)
    {
        tx.vout[0].nValue -= 1000000;
        hash = tx.GetHash();
        bool spendsCoinbase = (i == 0) ? true : false; // only first tx spends coinbase
        // If we don't set the # of sig ops in the CTxMemPoolEntry, template creation fails
        mempool.addUnchecked(hash, entry.Fee(1000000).Time(GetTime()).SpendsCoinbase(spendsCoinbase).FromTx(tx));
        tx.vin[0].prevout.hash = hash;
    }
    BOOST_CHECK_THROW(CreateNewBlock(chainparams, scriptPubKey), std::runtime_error);
    mempool.clear();

    // orphan in mempool, template creation fails
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Fee(1000000).Time(GetTime()).FromTx(tx));
    BOOST_CHECK_THROW(CreateNewBlock(chainparams, scriptPubKey), std::runtime_error);
    mempool.clear();

    // child with higher priority than parent
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vin[0].prevout.hash = txFirst[1]->GetHash();
    tx.vout[0].nValue = 49000000000LL;
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Fee(1000000000LL).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    tx.vin[0].prevout.hash = hash;
    tx.vin.resize(2);
    tx.vin[1].scriptSig = CScript() << OP_1;
    tx.vin[1].prevout.hash = txFirst[0]->GetHash();
    tx.vin[1].prevout.n = 0;
    tx.vout[0].nValue = 59000000000LL;
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Fee(4000000000LL).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    //BOOST_CHECK(pblocktemplate = CreateNewBlock(chainparams, scriptPubKey));
    //delete pblocktemplate;
    mempool.clear();

    // coinbase in mempool, template creation fails
    tx.vin.resize(1);
    tx.vin[0].prevout.SetNull();
    tx.vin[0].scriptSig = CScript() << OP_0 << OP_1;
    tx.vout[0].nValue = 0;
    hash = tx.GetHash();
    // give it a fee so it'll get mined
    mempool.addUnchecked(hash, entry.Fee(100000).Time(GetTime()).SpendsCoinbase(false).FromTx(tx));
    //BOOST_CHECK_THROW(CreateNewBlock(chainparams, scriptPubKey), std::runtime_error);
    mempool.clear();
#if 0

    // invalid (pre-p2sh) txn in mempool, template creation fails
    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vin[0].prevout.n = 0;
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vout[0].nValue = 49000000000LL;
    script = CScript() << OP_0;
    tx.vout[0].scriptPubKey = GetScriptForDestination(CScriptID(script));
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Fee(100000000L).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    tx.vin[0].prevout.hash = hash;
    tx.vin[0].scriptSig = CScript() << std::vector<unsigned char>(script.begin(), script.end());
    tx.vout[0].nValue -= 1000000;
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Fee(1000000).Time(GetTime()).SpendsCoinbase(false).FromTx(tx));
    //BOOST_CHECK_THROW(CreateNewBlock(chainparams, scriptPubKey), std::runtime_error);
    mempool.clear();

    // double spend txn pair in mempool, template creation fails
    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vout[0].nValue = 49000000000LL;
    tx.vout[0].scriptPubKey = CScript() << OP_1;
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Fee(1000000000L).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    tx.vout[0].scriptPubKey = CScript() << OP_2;
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Fee(1000000000L).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    //BOOST_CHECK_THROW(CreateNewBlock(chainparams, scriptPubKey), std::runtime_error);
    mempool.clear();

    // subsidy changing
    // int nHeight = chainActive.Height();
    // // Create an actual 209999-long block chain (without valid blocks).
    // while (chainActive.Tip()->nHeight < 209999) {
    //     CBlockIndex* prev = chainActive.Tip();
    //     CBlockIndex* next = new CBlockIndex();
    //     next->phashBlock = new uint256(GetRandHash());
    //     pcoinsTip->SetBestBlock(next->GetBlockHash());
    //     next->pprev = prev;
    //     next->nHeight = prev->nHeight + 1;
    //     next->BuildSkip();
    //     chainActive.SetTip(next);
    // }
    // BOOST_CHECK(pblocktemplate = CreateNewBlock(chainparams, scriptPubKey));
    // delete pblocktemplate;
    // // Extend to a 210000-long block chain.
    // while (chainActive.Tip()->nHeight < 210000) {
    //     CBlockIndex* prev = chainActive.Tip();
    //     CBlockIndex* next = new CBlockIndex();
    //     next->phashBlock = new uint256(GetRandHash());
    //     pcoinsTip->SetBestBlock(next->GetBlockHash());
    //     next->pprev = prev;
    //     next->nHeight = prev->nHeight + 1;
    //     next->BuildSkip();
    //     chainActive.SetTip(next);
    // }
    // BOOST_CHECK(pblocktemplate = CreateNewBlock(chainparams, scriptPubKey));
    // delete pblocktemplate;
    // // Delete the dummy blocks again.
    // while (chainActive.Tip()->nHeight > nHeight) {
    //     CBlockIndex* del = chainActive.Tip();
    //     chainActive.SetTip(del->pprev);
    //     pcoinsTip->SetBestBlock(del->pprev->GetBlockHash());
    //     delete del->phashBlock;
    //     delete del;
    // }

    // non-final txs in mempool
    SetMockTime(chainActive.Tip()->GetMedianTimePast()+1);
    int flags = LOCKTIME_VERIFY_SEQUENCE|LOCKTIME_MEDIAN_TIME_PAST;
    // height map
    std::vector<int> prevheights;

    // relative height locked
    tx.nVersion = 2;
    tx.vin.resize(1);
    prevheights.resize(1);
    tx.vin[0].prevout.hash = txFirst[0]->GetHash(); // only 1 transaction
    tx.vin[0].prevout.n = 0;
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vin[0].nSequence = chainActive.Tip()->nHeight + 1; // txFirst[0] is the 2nd block
    prevheights[0] = baseheight + 1;
    tx.vout.resize(1);
    tx.vout[0].nValue = 49000000000LL;
    tx.vout[0].scriptPubKey = CScript() << OP_1;
    tx.nLockTime = 0;
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Fee(1000000000L).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    //BOOST_CHECK(CheckFinalTx(tx, flags)); // Locktime passes
    //BOOST_CHECK(!TestSequenceLocks(tx, flags)); // Sequence locks fail
    //BOOST_CHECK(SequenceLocks(tx, flags, &prevheights, CreateBlockIndex(chainActive.Tip()->nHeight + 2))); // Sequence locks pass on 2nd block

    // relative time locked
    tx.vin[0].prevout.hash = txFirst[1]->GetHash();
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | (((chainActive.Tip()->GetMedianTimePast()+1-chainActive[1]->GetMedianTimePast()) >> CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) + 1); // txFirst[1] is the 3rd block
    prevheights[0] = baseheight + 2;
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Time(GetTime()).FromTx(tx));
    //BOOST_CHECK(CheckFinalTx(tx, flags)); // Locktime passes
    //BOOST_CHECK(!TestSequenceLocks(tx, flags)); // Sequence locks fail

    for (int i = 0; i < CBlockIndex::nMedianTimeSpan; i++)
        chainActive.Tip()->GetAncestor(chainActive.Tip()->nHeight - i)->nTime += 512; //Trick the MedianTimePast
    BOOST_CHECK(SequenceLocks(tx, flags, &prevheights, CreateBlockIndex(chainActive.Tip()->nHeight + 1))); // Sequence locks pass 512 seconds later
    for (int i = 0; i < CBlockIndex::nMedianTimeSpan; i++)
        chainActive.Tip()->GetAncestor(chainActive.Tip()->nHeight - i)->nTime -= 512; //undo tricked MTP

    // absolute height locked
    tx.vin[0].prevout.hash = txFirst[2]->GetHash();
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL - 1;
    prevheights[0] = baseheight + 3;
    tx.nLockTime = chainActive.Tip()->nHeight + 1;
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Time(GetTime()).FromTx(tx));
    BOOST_CHECK(!CheckFinalTx(tx, flags)); // Locktime fails
    BOOST_CHECK(TestSequenceLocks(tx, flags)); // Sequence locks pass
    BOOST_CHECK(IsFinalTx(tx, chainActive.Tip()->nHeight + 2, chainActive.Tip()->GetMedianTimePast())); // Locktime passes on 2nd block

    // absolute time locked
    tx.vin[0].prevout.hash = txFirst[3]->GetHash();
    tx.nLockTime = chainActive.Tip()->GetMedianTimePast();
    prevheights.resize(1);
    prevheights[0] = baseheight + 4;
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Time(GetTime()).FromTx(tx));
    BOOST_CHECK(!CheckFinalTx(tx, flags)); // Locktime fails
    BOOST_CHECK(TestSequenceLocks(tx, flags)); // Sequence locks pass
    BOOST_CHECK(IsFinalTx(tx, chainActive.Tip()->nHeight + 2, chainActive.Tip()->GetMedianTimePast() + 1)); // Locktime passes 1 second later

    // mempool-dependent transactions (not added)
    tx.vin[0].prevout.hash = hash;
    prevheights[0] = chainActive.Tip()->nHeight + 1;
    tx.nLockTime = 0;
    tx.vin[0].nSequence = 0;
    BOOST_CHECK(CheckFinalTx(tx, flags)); // Locktime passes
    BOOST_CHECK(TestSequenceLocks(tx, flags)); // Sequence locks pass
    tx.vin[0].nSequence = 1;
    BOOST_CHECK(!TestSequenceLocks(tx, flags)); // Sequence locks fail
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG;
    BOOST_CHECK(TestSequenceLocks(tx, flags)); // Sequence locks pass
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | 1;
    BOOST_CHECK(!TestSequenceLocks(tx, flags)); // Sequence locks fail

    BOOST_CHECK(pblocktemplate = CreateNewBlock(chainparams, scriptPubKey));

    // None of the of the absolute height/time locked tx should have made
    // it into the template because we still check IsFinalTx in CreateNewBlock,
    // but relative locked txs will if inconsistently added to mempool.
    // For now these will still generate a valid template until BIP68 soft fork
    BOOST_CHECK_EQUAL(pblocktemplate->block.vtx.size(), 3);
    delete pblocktemplate;
    // However if we advance height by 1 and time by 512, all of them should be mined
    for (int i = 0; i < CBlockIndex::nMedianTimeSpan; i++)
        chainActive.Tip()->GetAncestor(chainActive.Tip()->nHeight - i)->nTime += 512; //Trick the MedianTimePast
    chainActive.Tip()->nHeight++;
    SetMockTime(chainActive.Tip()->GetMedianTimePast() + 1);

    BOOST_CHECK(pblocktemplate = CreateNewBlock(chainparams, scriptPubKey));
    BOOST_CHECK_EQUAL(pblocktemplate->block.vtx.size(), 5);
    delete pblocktemplate;

    chainActive.Tip()->nHeight--;
    SetMockTime(0);
    mempool.clear();
#endif
    BOOST_FOREACH(CTransaction *tx, txFirst)
        delete tx;

    fCheckpointsEnabled = true;

}

BOOST_AUTO_TEST_SUITE_END()
