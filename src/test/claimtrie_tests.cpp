// Copyright (c) 2015 The LBRY Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://opensource.org/licenses/mit-license.php

#include "main.h"
#include "consensus/validation.h"
#include "consensus/merkle.h"
#include "primitives/transaction.h"
#include "miner.h"
#include "txmempool.h"
#include "claimtrie.h"
#include "nameclaim.h"
#include "arith_uint256.h"
#include "coins.h"
#include "streams.h"
#include "chainparams.h"
#include "policy/policy.h"
#include "pow.h"
#include <boost/test/unit_test.hpp>
#include <iostream>
#include "test/test_ulord.h"

using namespace std;

CScript scriptPubKey = CScript() << OP_TRUE;

BOOST_FIXTURE_TEST_SUITE(claimtrie_tests, RegTestingSetup)

CMutableTransaction BuildTransaction(const uint256& prevhash)
{
    CMutableTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;
    tx.vin.resize(1);
    tx.vout.resize(1);
    tx.vin[0].prevout.hash = prevhash;
    tx.vin[0].prevout.n = 0;
    tx.vin[0].scriptSig = CScript();
    tx.vin[0].nSequence = std::numeric_limits<unsigned int>::max();
    tx.vout[0].scriptPubKey = CScript();
    tx.vout[0].nValue = 0;

    return tx;
}

CMutableTransaction BuildTransaction(const CMutableTransaction& prev, uint32_t prevout=0, unsigned int numOutputs=1)
{
    CMutableTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;
    tx.vin.resize(1);
    tx.vout.resize(numOutputs);
    tx.vin[0].prevout.hash = prev.GetHash();
    tx.vin[0].prevout.n = prevout;
    tx.vin[0].scriptSig = CScript();
    tx.vin[0].nSequence = std::numeric_limits<unsigned int>::max();
    CAmount valuePerOutput = prev.vout[prevout].nValue;
    unsigned int numOutputsCopy = numOutputs;
    while ((numOutputsCopy = numOutputsCopy >> 1) > 0)
    {
        valuePerOutput = valuePerOutput >> 1;
    }
    for (unsigned int i = 0; i < numOutputs; ++i)
    {
        tx.vout[i].scriptPubKey = CScript();
        tx.vout[i].nValue = valuePerOutput;
    }

    return tx;
}

CMutableTransaction BuildTransaction(const CTransaction& prev, uint32_t prevout=0, unsigned int numOutputs=1)
{
    return BuildTransaction(CMutableTransaction(prev), prevout, numOutputs);
}

void AddToMempool(CMutableTransaction& tx)
{
    //CCoinsView dummy;
    //CCoinsViewCache view(&dummy);
    //CAmount inChainInputValue;
    //double dPriority = view.GetPriority(tx, chainActive.Height(), inChainInputValue);
    //unsigned int nSigOps = GetLegacySigOpCount(tx);
    //nSigOps += GetP2SHSigOpCount(tx, view);
    //LockPoints lp;
    //BOOST_CHECK(CheckSequenceLocks(tx, STANDARD_LOCKTIME_VERIFY_FLAGS, &lp));
    //mempool.addUnchecked(tx.GetHash(), CTxMemPoolEntry(tx, 0, GetTime(), 111.1, chainActive.Height(), mempool.HasNoInputsOf(tx), 10000000000, false, nSigOps, lp));
    CValidationState state;
    
    BOOST_CHECK(AcceptToMemoryPool(mempool, state, tx, false, NULL));
    //TestMemPoolEntryHelper entry;
    //entry.nFee = 11;
    //entry.dPriority = 111.0;
    //entry.nHeight = 11;
    //mempool.addUnchecked(tx.GetHash(), entry.Fee(10000).Time(GetTime()).FromTx(tx));
}

bool CreateBlock(CBlockTemplate* pblocktemplate)
{
    static int unique_block_counter = 0;
    const CChainParams& chainparams = Params(CBaseChainParams::REGTEST);
    CBlock* pblock = &pblocktemplate->block;
    pblock->nVersion = 1;
    pblock->nTime = chainActive.Tip()->GetBlockTime()+Params().GetConsensus().nPowTargetSpacing;
    CMutableTransaction txCoinbase(pblock->vtx[0]);
    txCoinbase.vin[0].scriptSig = CScript() << CScriptNum(unique_block_counter++) << CScriptNum(chainActive.Height());
    txCoinbase.vout[0].nValue = GetBlockSubsidy(chainActive.Height() + 1, chainparams.GetConsensus());
    pblock->vtx[0] = CTransaction(txCoinbase);
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
    pblock->nBits=GetNextWorkRequired(chainActive.Tip(),pblock,chainparams.GetConsensus());
    for (arith_uint256 i = 0; ; ++i)
    {
		pblock->nNonce = ArithToUint256(i);
        if (CheckProofOfWork(pblock->GetHash(), pblock->nBits, chainparams.GetConsensus()))
        {
            break;
        }
    }
    CValidationState state;
    bool success = (ProcessNewBlock(state, chainparams, NULL, pblock, true, NULL) && state.IsValid() && pblock->GetHash() == chainActive.Tip()->GetBlockHash());
	
    pblock->hashPrevBlock = pblock->GetHash();
    return success;
}

bool RemoveBlock(uint256& blockhash)
{
    CValidationState state;
    if (mapBlockIndex.count(blockhash) == 0)
        return false;
    CBlockIndex* pblockindex = mapBlockIndex[blockhash];
    InvalidateBlock(state, Params().GetConsensus(), pblockindex);
    if (state.IsValid())
    {
        ActivateBestChain(state, Params());
    }
    mempool.clear();
    return state.IsValid();

}

bool CreateCoinbases(unsigned int num_coinbases, std::vector<CTransaction>& coinbases)
{
    CBlockTemplate *pblocktemplate;
    coinbases.clear();
    BOOST_CHECK(pblocktemplate = CreateNewBlock(Params(), scriptPubKey));
    BOOST_CHECK(pblocktemplate->block.vtx.size() == 1);
    pblocktemplate->block.hashPrevBlock = chainActive.Tip()->GetBlockHash();
    for (unsigned int i = 0; i < 100 + num_coinbases; ++i)
    {
        BOOST_CHECK(CreateBlock(pblocktemplate));
        if (coinbases.size() < num_coinbases)
            coinbases.push_back(CTransaction(pblocktemplate->block.vtx[0]));
    }
    delete pblocktemplate;
    return true;
}

bool CreateBlocks(unsigned int num_blocks, unsigned int num_txs)
{
    CBlockTemplate *pblocktemplate;
    BOOST_CHECK(pblocktemplate = CreateNewBlock(Params(), scriptPubKey));
    BOOST_CHECK(pblocktemplate->block.vtx.size() == num_txs);
    pblocktemplate->block.hashPrevBlock = chainActive.Tip()->GetBlockHash();
    for (unsigned int i = 0; i <num_blocks; ++i)
    {
        BOOST_CHECK(CreateBlock(pblocktemplate));
    }
    delete pblocktemplate;
    return true;
}

BOOST_AUTO_TEST_CASE(claimtrie_insert_update_claim)
{
    
    fRequireStandard = false;
    BOOST_CHECK(pclaimTrie->nCurrentHeight == chainActive.Height() + 1);
    LOCK(cs_main);

    std::string sName1("atest");
    std::string sName2("btest");
    std::string sName3("atest123");
    std::string sValue1("testa");
    std::string sValue2("testb");
    std::string sValue3("123testa");

    std::vector<unsigned char> vchName1(sName1.begin(), sName1.end());
    std::vector<unsigned char> vchName2(sName2.begin(), sName2.end());
    std::vector<unsigned char> vchName3(sName3.begin(), sName3.end());
    std::vector<unsigned char> vchValue1(sValue1.begin(), sValue1.end());
    std::vector<unsigned char> vchValue2(sValue2.begin(), sValue2.end());
    std::vector<unsigned char> vchValue3(sValue3.begin(), sValue3.end());

    std::vector<CTransaction> coinbases;

    BOOST_CHECK(CreateCoinbases(6, coinbases));

    uint256 hash0(uint256S("0000000000000000000000000000000000000000000000000000000000000001"));
    //BOOST_CHECK(pclaimTrie->getMerkleHash() == hash0);
    
    CMutableTransaction tx1 = BuildTransaction(coinbases[1]);
    tx1.vout[0].scriptPubKey = CScript() << OP_CLAIM_NAME << vchName1 << vchValue1 << OP_2DROP << OP_DROP << OP_TRUE;
    uint160 tx1ClaimId = ClaimIdHash(tx1.GetHash(), 0);
    std::vector<unsigned char> vchTx1ClaimId(tx1ClaimId.begin(), tx1ClaimId.end());
    COutPoint tx1OutPoint(tx1.GetHash(), 0);

    CMutableTransaction tx2 = BuildTransaction(coinbases[1]);
    tx2.vout[0].scriptPubKey = CScript() << OP_CLAIM_NAME << vchName2 << vchValue2 << OP_2DROP << OP_DROP << OP_TRUE;
    tx2.vout[0].nValue = tx1.vout[0].nValue - 1;
    COutPoint tx2OutPoint(tx2.GetHash(), 0);
    
    CMutableTransaction tx3 = BuildTransaction(tx1);
    tx3.vout[0].scriptPubKey = CScript() << OP_UPDATE_CLAIM << vchName1 << vchTx1ClaimId << vchValue1 << OP_2DROP << OP_2DROP << OP_TRUE;
    tx3.vout[0].nValue -= 10000;
    COutPoint tx3OutPoint(tx3.GetHash(), 0);
    
    CMutableTransaction tx4 = BuildTransaction(tx2);
    tx4.vout[0].scriptPubKey = CScript() << OP_TRUE;
    COutPoint tx4OutPoint(tx4.GetHash(), 0);
    
    CMutableTransaction tx5 = BuildTransaction(coinbases[2]);
    tx5.vout[0].scriptPubKey = CScript() << OP_CLAIM_NAME << vchName2 << vchValue2 << OP_2DROP << OP_DROP << OP_TRUE;
    COutPoint tx5OutPoint(tx5.GetHash(), 0);
    
    CMutableTransaction tx6 = BuildTransaction(tx3);
    tx6.vout[0].scriptPubKey = CScript() << OP_TRUE;
    COutPoint tx6OutPoint(tx6.GetHash(), 0);
    
    CMutableTransaction tx7 = BuildTransaction(coinbases[3]);
    tx7.vout[0].scriptPubKey = CScript() << OP_CLAIM_NAME << vchName1 << vchValue2 << OP_2DROP << OP_DROP << OP_TRUE;
    tx7.vout[0].nValue = tx1.vout[0].nValue - 10001;
    uint160 tx7ClaimId = ClaimIdHash(tx7.GetHash(), 0);
    std::vector<unsigned char> vchTx7ClaimId(tx7ClaimId.begin(), tx7ClaimId.end());
    COutPoint tx7OutPoint(tx7.GetHash(), 0);
    
    CMutableTransaction tx8 = BuildTransaction(tx3, 0, 2);
    tx8.vout[0].scriptPubKey = CScript() << OP_UPDATE_CLAIM << vchName1 << vchTx1ClaimId << vchValue1 << OP_2DROP << OP_2DROP << OP_TRUE;
    tx8.vout[0].nValue = tx8.vout[0].nValue - 1;
    tx8.vout[1].scriptPubKey = CScript() << OP_CLAIM_NAME << vchName1 << vchValue2 << OP_2DROP << OP_DROP << OP_TRUE;
    COutPoint tx8OutPoint0(tx8.GetHash(), 0);
    COutPoint tx8OutPoint1(tx8.GetHash(), 1);
    
    CMutableTransaction tx9 = BuildTransaction(tx7);
    tx9.vout[0].scriptPubKey = CScript() << OP_UPDATE_CLAIM << vchName1 << vchTx7ClaimId << vchValue2 << OP_2DROP << OP_2DROP << OP_TRUE;
    tx9.vout[0].nValue -= 10000;
    COutPoint tx9OutPoint(tx9.GetHash(), 0);
    
    CMutableTransaction tx10 = BuildTransaction(coinbases[4]);
    tx10.vout[0].scriptPubKey = CScript() << OP_UPDATE_CLAIM << vchName1 << vchTx1ClaimId << vchValue1 << OP_2DROP << OP_2DROP << OP_TRUE;
    COutPoint tx10OutPoint(tx10.GetHash(), 0);

    CMutableTransaction tx11 = BuildTransaction(tx10);
    tx11.vout[0].scriptPubKey = CScript() << OP_UPDATE_CLAIM << vchName1 << vchTx1ClaimId << vchValue1 << OP_2DROP << OP_2DROP << OP_TRUE;
    COutPoint tx11OutPoint(tx11.GetHash(), 0);

    CMutableTransaction tx12 = BuildTransaction(tx10);
    tx12.vout[0].scriptPubKey = CScript() << OP_TRUE;
    COutPoint tx12OutPoint(tx12.GetHash(), 0);

    CMutableTransaction tx13 = BuildTransaction(coinbases[5]);
    tx13.vout[0].scriptPubKey = CScript() << OP_CLAIM_NAME << vchName3 << vchValue3 << OP_2DROP << OP_DROP << OP_TRUE;
    COutPoint tx13OutPoint(tx13.GetHash(), 0);
    
    CClaimValue val;

    int nThrowaway;

    std::vector<uint256> blocks_to_invalidate;

    // Verify claims for uncontrolled names go in immediately

    AddToMempool(tx7);

    BOOST_CHECK(CreateBlocks(1, 2));
    blocks_to_invalidate.push_back(chainActive.Tip()->GetBlockHash());
    
    BOOST_CHECK(pclaimTrie->getInfoForName(sName1, val));
    BOOST_CHECK(val.outPoint == tx7OutPoint);

    // Verify claims for controlled names are delayed, and that the bigger claim wins when inserted

    BOOST_CHECK(CreateBlocks(5, 1));

    AddToMempool(tx1);

    BOOST_CHECK(CreateBlocks(1, 2));

    BOOST_CHECK(!pclaimTrie->queueEmpty());

    BOOST_CHECK(CreateBlocks(5, 1));

    BOOST_CHECK(!pclaimTrie->queueEmpty());

    BOOST_CHECK(CreateBlocks(1, 1));

    BOOST_CHECK(pclaimTrie->queueEmpty());
    BOOST_CHECK(pclaimTrie->getInfoForName(sName1, val));
    BOOST_CHECK(val.outPoint == tx1OutPoint);
    
    // Verify updates to the best claim get inserted immediately, and others don't.

    AddToMempool(tx3);
    AddToMempool(tx9);

    BOOST_CHECK(CreateBlocks(1, 3));
    blocks_to_invalidate.push_back(chainActive.Tip()->GetBlockHash());

    BOOST_CHECK(!pclaimTrie->queueEmpty());
    BOOST_CHECK(!pclaimTrie->haveClaim(sName1, tx1OutPoint));
    BOOST_CHECK(!pclaimTrie->haveClaim(sName1, tx7OutPoint));
    BOOST_CHECK(pclaimTrie->getInfoForName(sName1, val));
    BOOST_CHECK(val.outPoint == tx3OutPoint);
    BOOST_CHECK(pclaimTrie->haveClaimInQueue(sName1, tx9OutPoint, nThrowaway));

    // Disconnect all blocks until the first block, and then reattach them, in memory only

    //FlushStateToDisk();

    CCoinsViewCache coins(pcoinsTip);
    CClaimTrieCache trieCache(pclaimTrie);
    CBlockIndex* pindexState = chainActive.Tip();
    CValidationState state;
    CBlockIndex* pindex;
    for (pindex = chainActive.Tip(); pindex && pindex->pprev; pindex=pindex->pprev)
    {
        CBlock block;
        BOOST_CHECK(ReadBlockFromDisk(block, pindex, Params().GetConsensus()));
        if (pindex == pindexState && (coins.DynamicMemoryUsage() + pcoinsTip->DynamicMemoryUsage()) <= nCoinCacheUsage)
        {
            bool fClean = true;
            BOOST_CHECK(DisconnectBlock(block, state, pindex, coins, trieCache, &fClean));
            pindexState = pindex->pprev;
        }
    }
    while (pindex != chainActive.Tip())
    {
        pindex = chainActive.Next(pindex);
        CBlock block;
        BOOST_CHECK(ReadBlockFromDisk(block, pindex, Params().GetConsensus()));
        BOOST_CHECK(ConnectBlock(block, state, pindex, coins, trieCache));
    }
    
    // Roll back the last block, make sure tx1 and tx7 are put back in the trie

    BOOST_CHECK(RemoveBlock(blocks_to_invalidate.back()));
    blocks_to_invalidate.pop_back();
    BOOST_CHECK(pclaimTrie->getInfoForName(sName1, val));
    BOOST_CHECK(val.outPoint == tx1OutPoint);
    BOOST_CHECK(pclaimTrie->haveClaim(sName1, tx7OutPoint));
    BOOST_CHECK(pclaimTrie->queueEmpty());
    BOOST_CHECK(!pclaimTrie->empty());

    // Roll all the way back, make sure all txs are out of the trie

    BOOST_CHECK(RemoveBlock(blocks_to_invalidate.back()));
    blocks_to_invalidate.pop_back();
    BOOST_CHECK(!pclaimTrie->getInfoForName(sName1, val));
    

    BOOST_CHECK(pclaimTrie->empty());
    BOOST_CHECK(pclaimTrie->getMerkleHash() == hash0);
    BOOST_CHECK(pclaimTrie->queueEmpty());

    // Test undoing a claim before the claim gets into the trie

    // Put tx1 in the chain, then advance a few blocks.
    
    AddToMempool(tx1);

    BOOST_CHECK(CreateBlocks(1, 2));
    blocks_to_invalidate.push_back(chainActive.Tip()->GetBlockHash());

    BOOST_CHECK(!pclaimTrie->empty());
    BOOST_CHECK(pclaimTrie->queueEmpty());

    BOOST_CHECK(CreateBlocks(10, 1));
    
    // Put tx7 in the chain, verify it goes into the queue

    AddToMempool(tx7);

    BOOST_CHECK(CreateBlocks(1, 2));
    blocks_to_invalidate.push_back(chainActive.Tip()->GetBlockHash());

    BOOST_CHECK(!pclaimTrie->empty());
    BOOST_CHECK(!pclaimTrie->queueEmpty());

    // Undo that block and make sure it's not in the queue

    BOOST_CHECK(RemoveBlock(blocks_to_invalidate.back()));
    blocks_to_invalidate.pop_back();

    // Make sure it's not in the queue

    BOOST_CHECK(!pclaimTrie->empty());
    BOOST_CHECK(pclaimTrie->queueEmpty());

    // Go back to the beginning

    BOOST_CHECK(RemoveBlock(blocks_to_invalidate.back()));
    blocks_to_invalidate.pop_back();
    BOOST_CHECK(pclaimTrie->empty());
    BOOST_CHECK(pclaimTrie->queueEmpty());

    // Test spend a claim which was just inserted into the trie

    // Immediately spend tx2 with tx4, verify nothing gets put in the trie

    AddToMempool(tx2);
    AddToMempool(tx4);

    BOOST_CHECK(CreateBlocks(1, 3));
    blocks_to_invalidate.push_back(chainActive.Tip()->GetBlockHash());

    BOOST_CHECK(pclaimTrie->empty());
    BOOST_CHECK(pclaimTrie->queueEmpty());

    BOOST_CHECK(RemoveBlock(blocks_to_invalidate.back()));
    blocks_to_invalidate.pop_back();
    BOOST_CHECK(pclaimTrie->empty());
    BOOST_CHECK(pclaimTrie->queueEmpty());

    // Verify that if a claim in the queue is spent, it does not get into the trie

    // Put tx5 into the chain, advance until it's in the trie for a few blocks

    AddToMempool(tx5);

    BOOST_CHECK(CreateBlocks(1, 2));
    blocks_to_invalidate.push_back(chainActive.Tip()->GetBlockHash());

    BOOST_CHECK(CreateBlocks(5, 1));
    
    // Put tx2 into the chain, and then advance a few blocks but not far enough for it to get into the trie

    AddToMempool(tx2);

    BOOST_CHECK(CreateBlocks(1, 2));
    
    BOOST_CHECK(pclaimTrie->haveClaimInQueue(sName2, tx2OutPoint, nThrowaway));
    
    BOOST_CHECK(!pclaimTrie->empty());
    BOOST_CHECK(!pclaimTrie->queueEmpty());

    BOOST_CHECK(CreateBlocks(3, 1));
    
    BOOST_CHECK(!pclaimTrie->empty());
    BOOST_CHECK(!pclaimTrie->queueEmpty());

    // Spend tx2 with tx4, and then advance to where tx2 would be inserted into the trie and verify it hasn't happened

    AddToMempool(tx4);
    
    BOOST_CHECK(CreateBlocks(1, 2));
    blocks_to_invalidate.push_back(chainActive.Tip()->GetBlockHash());
    
    BOOST_CHECK(!pclaimTrie->empty());
    BOOST_CHECK(pclaimTrie->queueEmpty());

    BOOST_CHECK(CreateBlocks(5, 1));
    
    BOOST_CHECK(!pclaimTrie->empty());
    BOOST_CHECK(pclaimTrie->queueEmpty());
    BOOST_CHECK(!pclaimTrie->haveClaim(sName2, tx2OutPoint));

    // Undo spending tx2 with tx4, and then advance and verify tx2 is inserted into the trie when it should be

    BOOST_CHECK(RemoveBlock(blocks_to_invalidate.back()));
    blocks_to_invalidate.pop_back();
    
    BOOST_CHECK(CreateBlocks(1, 1));
    
    BOOST_CHECK(!pclaimTrie->empty());
    BOOST_CHECK(!pclaimTrie->queueEmpty());

    BOOST_CHECK(pclaimTrie->haveClaimInQueue(sName2, tx2OutPoint, nThrowaway));
    
    BOOST_CHECK(CreateBlocks(2, 1));
    
    BOOST_CHECK(pclaimTrie->haveClaim(sName2, tx2OutPoint));

    BOOST_CHECK(!pclaimTrie->empty());
    BOOST_CHECK(pclaimTrie->queueEmpty());
    BOOST_CHECK(pclaimTrie->getInfoForName(sName2, val));
    BOOST_CHECK(val.outPoint == tx5OutPoint);
    BOOST_CHECK(pclaimTrie->haveClaim(sName2, tx2OutPoint));

    // Test undoing a spend which involves a claim in the trie

    // spend tx2, which is in the trie, with tx4
    
    AddToMempool(tx4);

    BOOST_CHECK(CreateBlocks(1, 2));
    blocks_to_invalidate.push_back(chainActive.Tip()->GetBlockHash());

    BOOST_CHECK(!pclaimTrie->empty());
    BOOST_CHECK(pclaimTrie->queueEmpty());
    BOOST_CHECK(!pclaimTrie->haveClaim(sName2, tx2OutPoint));

    // undo spending tx2 with tx4, and verify tx2 is back in the trie
    
    BOOST_CHECK(RemoveBlock(blocks_to_invalidate.back()));
    blocks_to_invalidate.pop_back();
    BOOST_CHECK(!pclaimTrie->empty());
    BOOST_CHECK(pclaimTrie->queueEmpty());
    BOOST_CHECK(pclaimTrie->getInfoForName(sName2, val));
    BOOST_CHECK(val.outPoint == tx5OutPoint);
    BOOST_CHECK(pclaimTrie->haveClaim(sName2, tx2OutPoint));

    // roll back to the beginning
    
    BOOST_CHECK(RemoveBlock(blocks_to_invalidate.back()));
    blocks_to_invalidate.pop_back();
    BOOST_CHECK(pclaimTrie->empty());
    BOOST_CHECK(pclaimTrie->queueEmpty());

    // Test undoing a spent update which updated a claim still in the queue

    // Create the claim that will cause the others to be in the queue

    AddToMempool(tx7);

    BOOST_CHECK(CreateBlocks(1, 2));
    blocks_to_invalidate.push_back(chainActive.Tip()->GetBlockHash());

    BOOST_CHECK(CreateBlocks(5, 1));

    // Create the original claim (tx1)

    AddToMempool(tx1);

    BOOST_CHECK(CreateBlocks(1, 2));
    //blocks_to_invalidate.push_back(chainActive.Tip()->GetBlockHash());

    BOOST_CHECK(!pclaimTrie->empty());
    BOOST_CHECK(!pclaimTrie->queueEmpty());
    BOOST_CHECK(pclaimTrie->haveClaimInQueue(sName1, tx1OutPoint, nThrowaway));

    // move forward some, but not far enough for the claim to get into the trie

    BOOST_CHECK(CreateBlocks(2, 1));
    
    // update the original claim (tx3 spends tx1)

    AddToMempool(tx3);

    BOOST_CHECK(CreateBlocks(1, 2));
    //blocks_to_invalidate.push_back(chainActive.Tip()->GetBlockHash());

    BOOST_CHECK(!pclaimTrie->empty());
    BOOST_CHECK(!pclaimTrie->queueEmpty());
    BOOST_CHECK(!pclaimTrie->haveClaimInQueue(sName1, tx1OutPoint, nThrowaway));
    BOOST_CHECK(!pclaimTrie->haveClaim(sName1, tx1OutPoint));
    BOOST_CHECK(pclaimTrie->haveClaimInQueue(sName1, tx3OutPoint, nThrowaway));

    // spend the update (tx6 spends tx3)

    AddToMempool(tx6);

    BOOST_CHECK(CreateBlocks(1, 2));
    blocks_to_invalidate.push_back(chainActive.Tip()->GetBlockHash());

    BOOST_CHECK(!pclaimTrie->empty());
    BOOST_CHECK(pclaimTrie->queueEmpty());
    BOOST_CHECK(!pclaimTrie->haveClaim(sName1, tx3OutPoint));

    // undo spending the update (undo tx6 spending tx3)

    BOOST_CHECK(RemoveBlock(blocks_to_invalidate.back()));
    blocks_to_invalidate.pop_back();
    BOOST_CHECK(!pclaimTrie->empty());
    BOOST_CHECK(!pclaimTrie->queueEmpty());

    // make sure the update (tx3) still goes into effect when it's supposed to

    BOOST_CHECK(CreateBlocks(8, 1));
    BOOST_CHECK(CreateBlocks(1, 1));

    BOOST_CHECK(!pclaimTrie->empty());
    BOOST_CHECK(pclaimTrie->queueEmpty());
    BOOST_CHECK(pclaimTrie->getInfoForName(sName1, val));
    BOOST_CHECK(val.outPoint == tx3OutPoint);

    BOOST_CHECK(CreateBlocks(1, 1));

    BOOST_CHECK(!pclaimTrie->empty());
    BOOST_CHECK(pclaimTrie->queueEmpty());
    BOOST_CHECK(pclaimTrie->haveClaim(sName1, tx3OutPoint));

    // roll all the way back

    BOOST_CHECK(RemoveBlock(blocks_to_invalidate.back()));
    blocks_to_invalidate.pop_back();
    BOOST_CHECK(pclaimTrie->empty());
    BOOST_CHECK(pclaimTrie->queueEmpty());

    // Test undoing an spent update which updated the best claim to a name

    // move forward until the original claim is inserted into the trie

    AddToMempool(tx1);

    BOOST_CHECK(CreateBlocks(1, 2));
    blocks_to_invalidate.push_back(chainActive.Tip()->GetBlockHash());

    BOOST_CHECK(!pclaimTrie->empty());
    BOOST_CHECK(pclaimTrie->queueEmpty());

    BOOST_CHECK(CreateBlocks(5, 1));

    BOOST_CHECK(!pclaimTrie->empty());
    BOOST_CHECK(pclaimTrie->queueEmpty());
    BOOST_CHECK(pclaimTrie->getInfoForName(sName1, val));
    BOOST_CHECK(val.outPoint == tx1OutPoint);

    // update the original claim (tx3 spends tx1)
    
    AddToMempool(tx3);
    
    BOOST_CHECK(CreateBlocks(1, 2));
    
    BOOST_CHECK(!pclaimTrie->empty());
    BOOST_CHECK(pclaimTrie->queueEmpty());
    BOOST_CHECK(pclaimTrie->getInfoForName(sName1, val));
    BOOST_CHECK(val.outPoint == tx3OutPoint);
    
    // spend the update (tx6 spends tx3)
    
    AddToMempool(tx6);
    
    BOOST_CHECK(CreateBlocks(1, 2));
    blocks_to_invalidate.push_back(chainActive.Tip()->GetBlockHash());
    
    BOOST_CHECK(pclaimTrie->empty());
    BOOST_CHECK(pclaimTrie->queueEmpty());
    
    // undo spending the update (undo tx6 spending tx3)
    
    BOOST_CHECK(RemoveBlock(blocks_to_invalidate.back()));
    blocks_to_invalidate.pop_back();
    BOOST_CHECK(!pclaimTrie->empty());
    BOOST_CHECK(pclaimTrie->queueEmpty());
    BOOST_CHECK(pclaimTrie->getInfoForName(sName1, val));
    BOOST_CHECK(val.outPoint == tx3OutPoint);

    // Test having two updates to a claim in the same transaction

    // Add both txouts (tx8 spends tx3)
    
    AddToMempool(tx8);

    BOOST_CHECK(CreateBlocks(1, 2));
    blocks_to_invalidate.push_back(chainActive.Tip()->GetBlockHash());

    // ensure txout 0 made it into the trie and txout 1 did not
    
    BOOST_CHECK(!pclaimTrie->empty());
    BOOST_CHECK(!pclaimTrie->queueEmpty());

    BOOST_CHECK(pclaimTrie->getInfoForName(sName1, val));
    BOOST_CHECK(val.outPoint == tx8OutPoint0);

    // roll forward until tx8 output 1 gets into the trie

    BOOST_CHECK(CreateBlocks(6, 1));

    BOOST_CHECK(!pclaimTrie->empty());
    BOOST_CHECK(!pclaimTrie->queueEmpty());

    BOOST_CHECK(CreateBlocks(1, 1));

    // ensure txout 1 made it into the trie and is now in control

    BOOST_CHECK(!pclaimTrie->empty());
    BOOST_CHECK(pclaimTrie->queueEmpty());

    BOOST_CHECK(pclaimTrie->getInfoForName(sName1, val));
    BOOST_CHECK(val.outPoint == tx8OutPoint1);

    // roll back to before tx8

    BOOST_CHECK(RemoveBlock(blocks_to_invalidate.back()));
    blocks_to_invalidate.pop_back();

    // roll all the way back

    BOOST_CHECK(RemoveBlock(blocks_to_invalidate.back()));
    blocks_to_invalidate.pop_back();
    BOOST_CHECK(pclaimTrie->empty());
    BOOST_CHECK(pclaimTrie->queueEmpty());

    // make sure invalid updates don't wreak any havoc

    // put tx1 into the trie

    AddToMempool(tx1);

    BOOST_CHECK(CreateBlocks(1, 2));
    blocks_to_invalidate.push_back(chainActive.Tip()->GetBlockHash());

    BOOST_CHECK(pclaimTrie->getInfoForName(sName1, val));
    BOOST_CHECK(val.outPoint == tx1OutPoint);
    BOOST_CHECK(pclaimTrie->queueEmpty());

    // advance a few blocks

    BOOST_CHECK(CreateBlocks(5, 1));

    // put in bad tx10

    AddToMempool(tx10);

    BOOST_CHECK(CreateBlocks(1, 2));

    blocks_to_invalidate.push_back(chainActive.Tip()->GetBlockHash());

    BOOST_CHECK(!pclaimTrie->haveClaimInQueue(sName1, tx10OutPoint, nThrowaway));
    BOOST_CHECK(pclaimTrie->queueEmpty());

    // roll back, make sure nothing bad happens

    BOOST_CHECK(RemoveBlock(blocks_to_invalidate.back()));
    blocks_to_invalidate.pop_back();

    // put it back in

    AddToMempool(tx10);

    BOOST_CHECK(CreateBlocks(1, 2));

    BOOST_CHECK(!pclaimTrie->haveClaimInQueue(sName1, tx10OutPoint, nThrowaway));
    BOOST_CHECK(pclaimTrie->queueEmpty());

    // update it

    AddToMempool(tx11);
    
    BOOST_CHECK(CreateBlocks(1, 2));
    
    blocks_to_invalidate.push_back(chainActive.Tip()->GetBlockHash());

    BOOST_CHECK(!pclaimTrie->haveClaimInQueue(sName1, tx11OutPoint, nThrowaway));
    BOOST_CHECK(pclaimTrie->queueEmpty());

    BOOST_CHECK(CreateBlocks(10, 1));

    BOOST_CHECK(!pclaimTrie->haveClaimInQueue(sName1, tx11OutPoint, nThrowaway));
    BOOST_CHECK(!pclaimTrie->haveClaim(sName1, tx11OutPoint));
    BOOST_CHECK(pclaimTrie->queueEmpty());

    // roll back to before the update

    BOOST_CHECK(RemoveBlock(blocks_to_invalidate.back()));
    blocks_to_invalidate.pop_back();

    BOOST_CHECK(!pclaimTrie->haveClaim(sName1, tx11OutPoint));
    BOOST_CHECK(!pclaimTrie->haveClaimInQueue(sName1, tx11OutPoint, nThrowaway));
    BOOST_CHECK(!pclaimTrie->haveClaim(sName1, tx10OutPoint));
    BOOST_CHECK(!pclaimTrie->haveClaimInQueue(sName1, tx10OutPoint, nThrowaway));
    BOOST_CHECK(pclaimTrie->queueEmpty());

    // make sure tx10 would have gotten into the trie, then run tests again
    
    BOOST_CHECK(CreateBlocks(10, 1));

    BOOST_CHECK(!pclaimTrie->haveClaim(sName1, tx10OutPoint));
    BOOST_CHECK(!pclaimTrie->haveClaimInQueue(sName1, tx10OutPoint, nThrowaway));
    BOOST_CHECK(pclaimTrie->queueEmpty());

    // update it

    AddToMempool(tx11);

    BOOST_CHECK(CreateBlocks(1, 2));

    BOOST_CHECK(!pclaimTrie->haveClaimInQueue(sName1, tx11OutPoint, nThrowaway));
    BOOST_CHECK(!pclaimTrie->haveClaim(sName1, tx11OutPoint));
    BOOST_CHECK(pclaimTrie->queueEmpty());

    // make sure tx11 would have gotten into the trie

    BOOST_CHECK(CreateBlocks(20, 1));

    BOOST_CHECK(!pclaimTrie->haveClaimInQueue(sName1, tx11OutPoint, nThrowaway));
    BOOST_CHECK(!pclaimTrie->haveClaim(sName1, tx11OutPoint));
    BOOST_CHECK(!pclaimTrie->haveClaimInQueue(sName1, tx10OutPoint, nThrowaway));
    BOOST_CHECK(!pclaimTrie->haveClaim(sName1, tx10OutPoint));
    BOOST_CHECK(pclaimTrie->queueEmpty());

    // roll all the way back

    BOOST_CHECK(RemoveBlock(blocks_to_invalidate.back()));
    blocks_to_invalidate.pop_back();

    // Put tx10 and tx11 in without tx1 in

    AddToMempool(tx10);

    BOOST_CHECK(CreateBlocks(1, 2));
    blocks_to_invalidate.push_back(chainActive.Tip()->GetBlockHash());

    BOOST_CHECK(pclaimTrie->empty());
    BOOST_CHECK(pclaimTrie->queueEmpty());

    // update with tx11

    AddToMempool(tx11);

    BOOST_CHECK(CreateBlocks(1, 2));
    blocks_to_invalidate.push_back(chainActive.Tip()->GetBlockHash());

    BOOST_CHECK(pclaimTrie->empty());
    BOOST_CHECK(pclaimTrie->queueEmpty());

    // roll back to before tx11

    BOOST_CHECK(RemoveBlock(blocks_to_invalidate.back()));
    blocks_to_invalidate.pop_back();

    // spent tx10 with tx12 instead which is not a claim operation of any kind

    AddToMempool(tx12);

    BOOST_CHECK(CreateBlocks(1, 2));

    BOOST_CHECK(pclaimTrie->empty());
    BOOST_CHECK(pclaimTrie->queueEmpty());

    // roll all the way back

    BOOST_CHECK(RemoveBlock(blocks_to_invalidate.back()));
    blocks_to_invalidate.pop_back();
    // make sure all claim for names which exist in the trie but have no
    // values get inserted immediately

    blocks_to_invalidate.push_back(chainActive.Tip()->GetBlockHash());

    AddToMempool(tx13);

    BOOST_CHECK(CreateBlocks(1, 2));

    BOOST_CHECK(!pclaimTrie->empty());
    BOOST_CHECK(pclaimTrie->queueEmpty());

    AddToMempool(tx1);

    BOOST_CHECK(CreateBlocks(1, 2));
    BOOST_CHECK(!pclaimTrie->empty());
    BOOST_CHECK(pclaimTrie->queueEmpty());

    // roll back

    BOOST_CHECK(RemoveBlock(blocks_to_invalidate.back()));
    blocks_to_invalidate.pop_back();
}

BOOST_AUTO_TEST_CASE(claimtrienode_serialize_unserialize)
{
    fRequireStandard = false;
    CDataStream ss(SER_DISK, 0);

    uint160 hash160;

    CClaimTrieNode n1;
    CClaimTrieNode n2;
    CClaimValue throwaway;
    
    ss << n1;
    ss >> n2;
    BOOST_CHECK(n1 == n2);

    n1.hash.SetHex("0000000000000000000000000000000000000000000000000000000000000001");
    BOOST_CHECK(n1 != n2);
    ss << n1;
    ss >> n2;
    BOOST_CHECK(n1 == n2);

    n1.hash.SetHex("a79e8a5b28f7fa5e8836a4b48da9988bdf56ce749f81f413cb754f963a516200");
    BOOST_CHECK(n1 != n2);
    ss << n1;
    ss >> n2;
    BOOST_CHECK(n1 == n2);

    CClaimValue v1(COutPoint(uint256S("0000000000000000000000000000000000000000000000000000000000000001"), 0), hash160, 50, 0, 100);
    CClaimValue v2(COutPoint(uint256S("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"), 1), hash160, 100, 1, 101);

    n1.insertClaim(v1);
    BOOST_CHECK(n1 != n2);
    ss << n1;
    ss >> n2;
    BOOST_CHECK(n1 == n2);

    n1.insertClaim(v2);
    BOOST_CHECK(n1 != n2);
    ss << n1;
    ss >> n2;
    BOOST_CHECK(n1 == n2);

    n1.removeClaim(v1.outPoint, throwaway);
    BOOST_CHECK(n1 != n2);
    ss << n1;
    ss >> n2;
    BOOST_CHECK(n1 == n2);

    n1.removeClaim(v2.outPoint, throwaway);
    BOOST_CHECK(n1 != n2);
    ss << n1;
    ss >> n2;
    BOOST_CHECK(n1 == n2);
}

bool verify_proof(const CClaimTrieProof proof, uint256 rootHash, const std::string& name)
{
    uint256 previousComputedHash;
    std::string computedReverseName;
    bool verifiedValue = false;

    for (std::vector<CClaimTrieProofNode>::const_reverse_iterator itNodes = proof.nodes.rbegin(); itNodes != proof.nodes.rend(); ++itNodes)
    {
        bool foundChildInChain = false;
        std::vector<unsigned char> vchToHash;
        for (std::vector<std::pair<unsigned char, uint256> >::const_iterator itChildren = itNodes->children.begin(); itChildren != itNodes->children.end(); ++itChildren)
        {
            vchToHash.push_back(itChildren->first);
            uint256 childHash;
            if (itChildren->second.IsNull())
            {
                if (previousComputedHash.IsNull())
                {
                    return false;
                }
                if (foundChildInChain)
                {
                    return false;
                }
                foundChildInChain = true;
                computedReverseName += itChildren->first;
                childHash = previousComputedHash;
            }
            else
            {
                childHash = itChildren->second;
            }
            vchToHash.insert(vchToHash.end(), childHash.begin(), childHash.end());
        }
        if (itNodes != proof.nodes.rbegin() && !foundChildInChain)
        {
            return false;
        }
        if (itNodes->hasValue)
        {
            uint256 valHash;
            if (itNodes->valHash.IsNull())
            {
                if (itNodes != proof.nodes.rbegin())
                {
                    return false;
                }
                if (!proof.hasValue)
                {
                    return false;
                }
                valHash = getValueHash(proof.outPoint,
                                       proof.nHeightOfLastTakeover);

                verifiedValue = true;
            }
            else
            {
                valHash = itNodes->valHash;
            }
            vchToHash.insert(vchToHash.end(), valHash.begin(), valHash.end());
        }
        else if (proof.hasValue && itNodes == proof.nodes.rbegin())
        {
            return false;
        }
        CHash256 hasher;
        std::vector<unsigned char> vchHash(hasher.OUTPUT_SIZE);
        hasher.Write(vchToHash.data(), vchToHash.size());
        hasher.Finalize(&(vchHash[0]));
        uint256 calculatedHash(vchHash);
        previousComputedHash = calculatedHash;
    }
    if (previousComputedHash != rootHash)
    {
        return false;
    }
    if (proof.hasValue && !verifiedValue)
    {
        return false;
    }
    std::string::reverse_iterator itComputedName = computedReverseName.rbegin();
    std::string::const_iterator itName = name.begin();
    for (; itName != name.end() && itComputedName != computedReverseName.rend(); ++itName, ++itComputedName)
    {
        if (*itName != *itComputedName)
        {
            return false;
        }
    }
    return (!proof.hasValue || itName == name.end());
}


BOOST_AUTO_TEST_SUITE_END()
