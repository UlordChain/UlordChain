// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2016-2018 The Ulord Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>
#include "arith_uint256.h"
#include "chainparamsseeds.h"

//#define GENESIS_GENERATION

#ifdef GENESIS_GENERATION
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <string>
#include "utiltime.h"
#include <random>
#include <cmath>

using namespace std;

typedef uint32_t uint;

static void findGenesis(CBlock *pblock, const string & net)
{
	fstream fout;
	fout.open("/root/" + net, ios::out | ios::app);
	if (!fout.is_open())
	{
		cerr << "chainparams.cpp, file error" << endl;
		return;
	}
	
	arith_uint256 hashTarget = arith_uint256().SetCompact(pblock->nBits);
	
	fout << " finding genesis using target " << hashTarget.ToString()
		 << ", " << net << endl;;
	cout << " finding genesis using target " << hashTarget.ToString()
		 << ", " << net << endl;

    std::random_device r;
        
    // choose random number in [1, max of uint32_t]
    std::default_random_engine el(r());
    std::uniform_int_distribution<uint> uniform_dist(1, std::numeric_limits<uint>::max());

	for (int cnt = 0; true; ++cnt)
	{
		uint256 hash = pblock->GetHash();
		cout << "calculating nonc = " << pblock->nNonce << ", hash = " << UintToArith256(hash).ToString() 
			 << ", target = " << hashTarget.ToString() << endl;
		fout << "calculating nonc = " << pblock->nNonce << ", hash = " << UintToArith256(hash).ToString() 
			 << ", target = " << hashTarget.ToString() << endl;
		if (UintToArith256(hash) <= hashTarget) break;
		pblock->nNonce = uniform_dist(el);
		if (cnt > 1e8)
		{
			pblock->nTime = GetTime();
			cnt = 0;
		}
	}
    
	cout << "\n\t\t----------------------------------------\t" << endl;
	fout << "\n\t\t----------------------------------------\t" << endl;
    cout << "\t" << pblock->ToString() << endl;
	fout << "\t" << pblock->ToString() << endl;
    cout << "\n\t\t----------------------------------------\t" << endl;
	fout << "\n\t\t----------------------------------------\t" << endl;

	fout.close();
}

#endif

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
	genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    genesis.hashClaimTrie = uint256S("0x1");
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=00000ffd590b14, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=e0028e, nTime=1390095618, nBits=1e0ffff0, nNonce=28917698, vtx=1)
 *   CTransaction(hash=e0028e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d01044c5957697265642030392f4a616e2f3230313420546865204772616e64204578706572696d656e7420476f6573204c6976653a204f76657273746f636b2e636f6d204973204e6f7720416363657074696e6720426974636f696e73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0xA9037BAC7050C479B121CF)
 *   vMerkleTree: e0028e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "You decide";
    const CScript genesisOutputScript = CScript() << ParseHex("041c508f27e982c369486c0f1a42779208b3f5dc96c21a2af6004cb18d1529f42182425db1e1632dc6e73ff687592e148569022cee52b4b4eb10e8bb11bd927ec0") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 210240; // Note: actual number of blocks per calendar year with DGW v3 is ~200700 (for example 449750 - 249050)
        consensus.nMasternodePaymentsStartBlock = 1500; // not true, but it's ok as long as it's less then nMasternodePaymentsIncreaseBlock
        consensus.nMasternodePaymentsIncreaseBlock = 158000; // actual historical value
        consensus.nMasternodePaymentsIncreasePeriod = 576*30; // 17280 - actual historical value
        consensus.nInstantSendKeepLock = 24;
        consensus.nBudgetPaymentsStartBlock = 1500; // actual historical value
        consensus.nBudgetPaymentsCycleBlocks = 16616; // ~(60*24*30)/2.6, actual number of blocks per month is 200700 / 12 = 16725
        consensus.nBudgetPaymentsWindowBlocks = 100;
        consensus.nBudgetProposalEstablishingTime = 60*60*24;
        consensus.nSuperblockStartBlock = 1501; // The block at which 12.1 goes live (end of final 12.0 budget cycle)
        consensus.nSuperblockCycle = 16616; // ~(60*24*30)/2.6, actual number of blocks per month is 200700 / 12 = 16725
        consensus.nGovernanceMinQuorum = 10;
        consensus.nGovernanceFilterElements = 20000;
        consensus.nMasternodeMinimumConfirmations = 15;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.BIP34Height = 0; 
        consensus.BIP34Hash = uint256S("0x000002287d4bdfb69539d264be0eae5f08c8f990732b84cb6c0834bcee80de3a");
        consensus.powLimit = uint256S("00000fffff000000000000000000000000000000000000000000000000000000");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPowTargetTimespan = 24 * 60 * 60; // Ulord: 1 day
        consensus.nPowTargetSpacing = 2.5 * 60; // Ulord: 2.5 minutes
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1515726624; // 2018/1/12 - Jan 12, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1547262624; // 2019/1/12 - Jan 12, 2019

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xb3;
        pchMessageStart[1] = 0x01;
        pchMessageStart[2] = 0x6f;
        pchMessageStart[3] = 0xb1;
        vAlertPubKey = ParseHex("04838a03bad39edd961c7b25ed87fd34ac234d4786c127b3d31f4ea529b08f26c4d50f3373ce247926eca129aa1d5aad2b68da546336533e24a497bee95195c36f");
        nDefaultPort = 9888;
        nMaxTipAge = 6 * 60 * 60; // ~144 blocks behind -> 2 x fork detection time, was 24 * 60 * 60 in bitcoin
        nPruneAfterHeight = 100000;

		// 
		genesis = CreateGenesisBlock(1515726624, 617631331, 0x1e0ffff0, 1, 50 * COIN);
#ifdef GENESIS_GENERATION
		findGenesis(&genesis, "main");
#endif
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x000002287d4bdfb69539d264be0eae5f08c8f990732b84cb6c0834bcee80de3a"));
        assert(genesis.hashMerkleRoot == uint256S("0xa99a8f5a07e99027549746cad7b082afe161e118b58387f6aad59e0cec7f5aa9"));

// temporarily commented out
/*
        vSeeds.push_back(CDNSSeedData("darkcoin.io", "dnsseed.darkcoin.io"));
        vSeeds.push_back(CDNSSeedData("ulorddot.io", "dnsseed.ulorddot.io"));
        vSeeds.push_back(CDNSSeedData("masternode.io", "dnsseed.masternode.io"));
        vSeeds.push_back(CDNSSieedData("ulordpay.io", "dnsseed.ulordpay.io"));
*/
        // Ulord addresses start with 'U'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,68);
        // Ulord script addresses start with '7'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,16);
        // Ulord private keys start with '7' or 'X'
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,204);
        // Ulord BIP32 pubkeys start with 'xpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        // Ulord BIP32 prvkeys start with 'xprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
        // Ulord BIP44 coin type is '5'
        base58Prefixes[EXT_COIN_TYPE]  = boost::assign::list_of(0x80)(0x00)(0x00)(0x05).convert_to_container<std::vector<unsigned char> >();

//        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));
		vFixedSeeds.clear();
		vSeeds.clear();		

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 60*60; // fulfilled requests expire in 1 hour
        strSporkPubKey = "044adbc8019f33ad556e99e73f00afa0fe50e9617fdc3098aac24125f517261822affad3ff5ea5f6e37ab39f9443b6912c4f8f806bb8c8bf5aa812a3dc0b3a8c55";
        strMasternodePaymentsPubKey = "047e9c232f68712e279eb5b399e3150f04a44b1c4f0d41a62a4f93b6b09e2c6cbb1cddfd14e1fad92f442432d4c452ab697f5366fda39b8a32002d39b667a9a5a3";

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
			(0, uint256S("000002287d4bdfb69539d264be0eae5f08c8f990732b84cb6c0834bcee80de3a")),
            1515726624, // * UNIX timestamp of last checkpoint block
            0,    // * total number of transactions between genesis and last checkpoint
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0        // * estimated number of transactions per day after checkpoint
        };
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 210240;
        consensus.nMasternodePaymentsStartBlock = 10000; // not true, but it's ok as long as it's less then nMasternodePaymentsIncreaseBlock
        consensus.nMasternodePaymentsIncreaseBlock = 46000;
        consensus.nMasternodePaymentsIncreasePeriod = 576;
        consensus.nInstantSendKeepLock = 6;
        consensus.nBudgetPaymentsStartBlock = 60000;
        consensus.nBudgetPaymentsCycleBlocks = 50;
        consensus.nBudgetPaymentsWindowBlocks = 10;
        consensus.nBudgetProposalEstablishingTime = 60*20;
        consensus.nSuperblockStartBlock = 61000; // NOTE: Should satisfy nSuperblockStartBlock > nBudgetPeymentsStartBlock
        consensus.nSuperblockCycle = 24; // Superblocks can be issued hourly on testnet
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 500;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 100;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("00000a98aa88364a5105f3d831368f823e14291a9cd2aba50d6eb5a416b97630");
        consensus.powLimit = uint256S("00000fffff000000000000000000000000000000000000000000000000000000");
		consensus.nPowAveragingWindow = 17;
		assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPowTargetTimespan = 24 * 60 * 60; // Ulord: 1 day
        consensus.nPowTargetSpacing = 2.5 * 60; // Ulord: 2.5 minutes
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1515726791; // Jan 12, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1547262791; // Jan 12, 2019

        pchMessageStart[0] = 0xc2;
        pchMessageStart[1] = 0xe6;
        pchMessageStart[2] = 0xce;
        pchMessageStart[3] = 0xf3;
        vAlertPubKey = ParseHex("041c508f27e982c369486c0f1a42779208b3f5dc96c21a2af6004cb18d1529f42182425db1e1632dc6e73ff687592e148569022cee52b4b4eb10e8bb11bd927ec0");
        nDefaultPort = 19888;
        nMaxTipAge = 0x7fffffff; // allow mining on top of old blocks for testnet
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1515726791, 1802250598, 0x1e0ffff0, 1,  50 * COIN);
#ifdef GENESIS_GENERATION
        findGenesis(&genesis, "testnet");
#endif
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00000a98aa88364a5105f3d831368f823e14291a9cd2aba50d6eb5a416b97630"));
        assert(genesis.hashMerkleRoot == uint256S("0xa99a8f5a07e99027549746cad7b082afe161e118b58387f6aad59e0cec7f5aa9"));

        vFixedSeeds.clear();
        vSeeds.clear();
/*
        vSeeds.push_back(CDNSSeedData("ulorddot.io",  "testnet-seed.ulorddot.io"));
        vSeeds.push_back(CDNSSeedData("masternode.io", "test.dnsseed.masternode.io"));
*/
        // Testnet Ulord addresses start with 'u'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,130);
        // Testnet Ulord script addresses start with '8' or '9'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,19);
        // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        // Testnet Ulord BIP32 pubkeys start with 'tpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        // Testnet Ulord BIP32 prvkeys start with 'tprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
        // Testnet Ulord BIP44 coin type is '1' (All coin's testnet default)
        base58Prefixes[EXT_COIN_TYPE]  = boost::assign::list_of(0x80)(0x00)(0x00)(0x01).convert_to_container<std::vector<unsigned char> >();

//        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes
        strSporkPubKey = "046f78dcf911fbd61910136f7f0f8d90578f68d0b3ac973b5040fb7afb501b5939f39b108b0569dca71488f5bbf498d92e4d1194f6f941307ffd95f75e76869f0e";
        strMasternodePaymentsPubKey = "046f78dcf911fbd61910136f7f0f8d90578f68d0b3ac973b5040fb7afb501b5939f39b108b0569dca71488f5bbf498d92e4d1194f6f941307ffd95f75e76869f0e";

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
			(0, uint256S("00000a98aa88364a5105f3d831368f823e14291a9cd2aba50d6eb5a416b97630")),
/*            (    261, uint256S("0x00000c26026d0815a7e2ce4fa270775f61403c040647ff2c3091f99e894a4618"))
            (   1999, uint256S("0x00000052e538d27fa53693efe6fb6892a0c1d26c0235f599171c48a3cce553b1"))
            (   2999, uint256S("0x0000024bc3f4f4cb30d29827c13d921ad77d2c6072e586c7f60d83c2722cdcc5"))
            (  12907, uint256S("0x00000067de20fd6d276ee0839a3187b203accaa5aad04ca5c17c2997e2730e4c"))
            (  15590, uint256S("0x00000009df8f2ee9c230aef9dad257d82bde20ca83378a208ce5d95d29a78852"))
            (  65900, uint256S("0x00000063e4e94d75d0dc075e93898444c8ef50655990dfff7c32d92a7efff671"))
            ( 127618, uint256S("0x0000002104a2c1fc923b0e3b74b1860236fbc2b4479a833c28abaf456ea4e466")),
*/
            1515726791, // * UNIX timestamp of last checkpoint block
            0,     // * total number of transactions between genesis and last checkpoint
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0         // * estimated number of transactions per day after checkpoint
        };
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMasternodePaymentsStartBlock = 240;
        consensus.nMasternodePaymentsIncreaseBlock = 350;
        consensus.nMasternodePaymentsIncreasePeriod = 10;
        consensus.nInstantSendKeepLock = 6;
        consensus.nBudgetPaymentsStartBlock = 1000;
        consensus.nBudgetPaymentsCycleBlocks = 50;
        consensus.nBudgetPaymentsWindowBlocks = 10;
        consensus.nBudgetProposalEstablishingTime = 60*20;
        consensus.nSuperblockStartBlock = 1500;
        consensus.nSuperblockCycle = 10;
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 100;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.BIP34Height = -1; // BIP34 has not necessarily activated on regtest
        consensus.BIP34Hash = uint256();
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
		assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 0; // Turn off adjustment down
        consensus.nPowMaxAdjustUp = 0; // Turn off adjustment up
        consensus.nPowTargetTimespan = 24 * 60 * 60; // Ulord: 1 day
        consensus.nPowTargetSpacing = 2.5 * 60; // Ulord: 2.5 minutes
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;

        pchMessageStart[0] = 0xf0;
        pchMessageStart[1] = 0xc5;
        pchMessageStart[2] = 0xbb;
        pchMessageStart[3] = 0xd0;
        nMaxTipAge = 6 * 60 * 60; // ~144 blocks behind -> 2 x fork detection time, was 24 * 60 * 60 in bitcoin
        nDefaultPort = 29888;
        nPruneAfterHeight = 1000;

		genesis = CreateGenesisBlock(1515545943, 1162212459, 0x207fffff, 1, 50 * COIN);
#ifdef GENESIS_GENERATION
        findGenesis(&genesis, "regtest");
#endif
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("145815522feb44a7c5da4eb261f9ef5fc142565e0998fb5ca7f558b5c250c09f"));
        assert(genesis.hashMerkleRoot == uint256S("a99a8f5a07e99027549746cad7b082afe161e118b58387f6aad59e0cec7f5aa9"));

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("145815522feb44a7c5da4eb261f9ef5fc142565e0998fb5ca7f558b5c250c09f")),
            0,
            0,
            0
        };
        // Regtest Ulord addresses start with 'u'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,130);
        // Regtest Ulord script addresses start with '8' or '9'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,19);
        // Regtest private keys start with '9' or 'c' (Bitcoin defaults)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        // Regtest Ulord BIP32 pubkeys start with 'tpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        // Regtest Ulord BIP32 prvkeys start with 'tprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
        // Regtest Ulord BIP44 coin type is '1' (All coin's testnet default)
        base58Prefixes[EXT_COIN_TYPE]  = boost::assign::list_of(0x80)(0x00)(0x00)(0x01).convert_to_container<std::vector<unsigned char> >();
   }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}
