// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2016-2018 The Ulord Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"
#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>
#include "arith_uint256.h"
#include "chainparamsseeds.h"

typedef int64_t i64;
//#define GENESIS_GENERATION

#ifdef GENESIS_GENERATION
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <string>
#include "utiltime.h"
#include <random>
#include <cmath>
#include <iomanip>

using namespace std;

typedef uint32_t uint;

static void findGenesis(CBlockHeader *pb, const string & net)
{
    fstream fout;
    fout.open("/root/" + net, ios::out | ios::app);
    if (!fout.is_open())
    {
        cerr << "chainparams.cpp, file error" << endl;
        return;
    }
	
    arith_uint256 hashTarget = arith_uint256().SetCompact(pb->nBits);
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
        uint256 hash = pb->GetHash();
        cout << "calculating nonce = " << setw(12) << pb->nNonce << ", time = " << pb->nTime;
        cout << ", hash = " << UintToArith256(hash).ToString() 
             << ", target = " << hashTarget.ToString() << endl;
        fout << "calculating nonce = " << setw(12) << pb->nNonce;
        fout << ", hash = " << UintToArith256(hash).ToString() 
             << ", target = " << hashTarget.ToString() << endl;
        if (UintToArith256(hash) <= hashTarget) break;
        pb->nNonce = uniform_dist(el);
        if (cnt > 1e2)
        {
            pb->nTime = GetTime();
            cnt = 0;
        }
    }
    
    cout << "\n\t\t----------------------------------------\t" << endl;
    fout << "\n\t\t----------------------------------------\t" << endl;
    cout << "\t" << pb->ToString() << endl;
    fout << "\t" << pb->ToString() << endl;
    cout << "\n\t\t----------------------------------------\t" << endl;
    fout << "\n\t\t----------------------------------------\t" << endl;

    fout.close();
}

#endif

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount &genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = CAmount(genesisReward);
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
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const i64& genesisReward)
{
    const char* pszTimestamp = "abracadabra";
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

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
	    // reward setting
	    consensus.premine = i64(1e8 * COIN);                            // premine
	    consensus.genesisReward = i64(1 * COIN);                        // genesis
	    consensus.minerReward4 = i64(112.966 * COIN);                   // miners
	    consensus.minerReward5 = i64(535.103 * COIN);
	    consensus.mnReward1 = i64(52.411 * COIN);                       // masternodes
	    consensus.mnReward2 = i64(76.104 * COIN);					
	    consensus.mnReward5 = i64(535.103 * COIN);
	    consensus.foundersReward = i64(4166666.667 * COIN);             // founders
     	consensus.bdgetReward4 = i64(520833.333 * COIN);                // budget
	    consensus.bdgetReward5 = i64(2083333.333 * COIN);

	    consensus.colleteral = i64(1e4 * COIN);                         // masternode colleteral

        consensus.nSubsidyHalvingInterval = 840960;                     // 4 years, 24 * 60 / 2.5 * 365 * 4 
        consensus.nMasternodePaymentsStartBlock = 57600;                // not true, but it's ok as long as it's less then nMasternodePaymentsIncreaseBlock
        consensus.nMasternodePaymentsIncreaseBlock = 576 * 365;         //576 * 365
        consensus.nMasternodePaymentsIncreasePeriod = 576 * 365;        // 17280 - actual historical value
        consensus.nInstantSendKeepLock = 24;
        consensus.nBudgetPaymentsStartBlock = 2;                        // actual historical value
        consensus.nBudgetPaymentsCycleBlocks = 576 * 30;                // ~(60*24*30)/2.6, actual number of blocks per month is 200700 / 12 = 16725
        consensus.nBudgetPaymentsWindowBlocks = 100;
        consensus.nBudgetProposalEstablishingTime = 60*60*24;
        consensus.nSuperblockStartBlock = 100;                          // The block at which 12.1 goes live (end of final 12.0 budget cycle)
        consensus.nSuperblockCycle = 576 * 30;                          // ~(60*24*30)/2.6, actual number of blocks per month is 200700 / 12 = 16725
        consensus.nSuperblockStartBlock = 100; 		//  The block at which 12.1 goes live (end of final 12.0 budget cycle)
        consensus.nSuperblockCycle = 576 * 30; 				// ~(60*24*30)/2.6, actual number of blocks per month is 200700 / 12 = 16725
        consensus.nGovernanceMinQuorum = 10;
        consensus.nGovernanceFilterElements = 20000;
        consensus.nMasternodeMinimumConfirmations = 15;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.BIP34Height = 0; 
        consensus.BIP34Hash = uint256S("0x00000f471d45750f8b9757728877fb50e0f867a10ca5fd3564be2bd521500446");
        consensus.powLimit = uint256S("00000fffff000000000000000000000000000000000000000000000000000000");
        consensus.nPowAveragingWindow = 17;
        consensus.nPowMaxAdjustDown = 32;                               // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16;                                 // 16% adjustment up
        consensus.nPowTargetTimespan = 24 * 60 * 60;                    // Ulord: 1 day
        consensus.nPowTargetSpacing = 2.5 * 60;                         // Ulord: 2.5 minutes
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916;                // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016;                      // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1517636489;              // Sat Feb  3 13:41:29 CST 2018 
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1549172489;                // Sun Feb  3 13:41:29 CST 2019

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

        genesis = CreateGenesisBlock(1517636489, 3393649461, 0x1e0ffff0, 1, consensus.genesisReward);
#ifdef GENESIS_GENERATION
        findGenesis(&genesis, "main");
#endif
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00000f471d45750f8b9757728877fb50e0f867a10ca5fd3564be2bd521500446"));
        assert(genesis.hashMerkleRoot == uint256S("0x2b5ff31e4f2bccf51441d2f78849c2ca393daa187cede58373ccad8f1794b8d9"));


        // Ulord addresses start with 'U'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,68);
        // Ulord script addresses start with 'S'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,63);
        // Ulord private keys start with '5' or 'K' or 'L'(as in Bitcoin)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,0x80);
        // Ulord BIP32 pubkeys start with 'xpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        // Ulord BIP32 prvkeys start with 'xprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
        // Ulord BIP44 coin type is '247'
        base58Prefixes[EXT_COIN_TYPE]  = boost::assign::list_of(0x80)(0x00)(0x00)(0xf7).convert_to_container<std::vector<unsigned char> >();

	    //vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));
	    vFixedSeeds.clear();
	    vSeeds.clear();		
        vSeeds.push_back(CDNSSeedData("ulord.one", "dnsseed1.ulord.one"));
        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 60*60; // fulfilled requests expire in 1 hour
        strSporkPubKey = "044adbc8019f33ad556e99e73f00afa0fe50e9617fdc3098aac24125f517261822affad3ff5ea5f6e37ab39f9443b6912c4f8f806bb8c8bf5aa812a3dc0b3a8c55";

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
	    (0, uint256S("00000f471d45750f8b9757728877fb50e0f867a10ca5fd3564be2bd521500446")),
            1517636489,                       // * UNIX timestamp of last checkpoint block
            0,                                // * total number of transactions between genesis and last checkpoint
                                              //   (the tx=... number in the SetBestChain debug.log lines)
            0                                 // * estimated number of transactions per day after checkpoint
        };

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = {
            "UNYu5sESPnFiYfUdPovQ4DkVZ1JUZRSDzH", /* main-index: 0*/
            "UNgxHBPF7E84jdG7vyUk8s8FTZBSkmsrvf", /* main-index: 1*/
            "UPYUKccNPUznkM7p7K77LxPC1u56WnHX8g", /* main-index: 2*/
            "UPmQ1Jpo8C3KuXikZ6V4VE7Ci6rSJ98SpF", /* main-index: 3*/
            "UQ4vWMrqMGX1Xh6EKH3PJqxAHAPpVqqaJF", /* main-index: 4*/
            "UQV3mydZX5wJ4mRack2neRZcEssQ9uMCEU", /* main-index: 5*/
            "URM5MvmnywdBrg2ydag4uGAJDtAs1kYHg1", /* main-index: 6*/
            "URi9L7PXpLAf6ka2CL26dGte6ZGoeYvmvY", /* main-index: 7*/
            "URzauhyLHsjubYXuzUpfUBgq4HH3Mr1Swc", /* main-index: 8*/
            "USVJWgzDs3Jf4uzaDMNgGjSqqwEkaFBEX7", /* main-index: 9*/
            "USdxtWPhmWvtBFGWaVRPuyHyqKWNMtHpKG", /* main-index: 10*/
            "USfoBmxrefRUaZVmVLcEYPQ8PfrG14MpbZ", /* main-index: 11*/
            "USnqJ73sPSJW5aRPfcQvJxzMiyTsAC9o1y", /* main-index: 12*/
            "USp1inLdJKoXKWZj3DTbAwfi5xrbWS89VM", /* main-index: 13*/
            "UTfhKVcm2UVbhC1TffcTEWq7dfxjTyQDpM", /* main-index: 14*/
            "UTyP5ak38ErHHMrMEr7sEy87q4d4QQymTb", /* main-index: 15*/
            "UTyZHmseooXwNTxZQQtrc4gKVF4cw2AYg1", /* main-index: 16*/
            "UUCRTjTnzAknJsgxRJcHXaG6gVMnRCAgEn", /* main-index: 17*/
            "UUPLH2XgRZWTShiDSQEpu6QdXwKgAf3LNM", /* main-index: 18*/
            "UUPLPbyre94vLQMDe2yvvucFHqX5ye4DXM", /* main-index: 19*/
            "UURodxCQSC8PW4BKFwQ6h3tBRgr8gxTTEu", /* main-index: 20*/
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
        // reward setting
	    consensus.premine = i64(1e8 * COIN);                            // premine
        consensus.genesisReward = i64(1 * COIN);                        // genesis                                                           
        consensus.minerReward4 = i64(112.966 * COIN);                   // miners
        consensus.minerReward5 = i64(535.103 * COIN);
        consensus.mnReward1 = i64(52.411 * COIN);                       // masternodes
        consensus.mnReward2 = i64(76.104 * COIN);
        consensus.mnReward5 = i64(535.103 * COIN);
        consensus.foundersReward = i64(4166666.667 * COIN);             // founders
        consensus.bdgetReward4 = i64(520833.333 * COIN);                // budget
        consensus.bdgetReward5 = i64(2083333.333 * COIN);
        consensus.colleteral = i64(1e4 * COIN);                         // masternode colleteral

        consensus.nSubsidyHalvingInterval = 840960;
        consensus.nMasternodePaymentsStartBlock = 100; 		        // not true, but it's ok as long as it's less then nMasternodePaymentsIncreaseBlock
        consensus.nMasternodePaymentsIncreaseBlock = 46000;
        consensus.nMasternodePaymentsIncreasePeriod = 576;
        consensus.nInstantSendKeepLock = 6;
        consensus.nBudgetPaymentsStartBlock = 300;
        consensus.nBudgetPaymentsCycleBlocks = 50;
        consensus.nBudgetPaymentsWindowBlocks = 10;
        consensus.nBudgetProposalEstablishingTime = 60*20;
        consensus.nSuperblockStartBlock = 60; 				 // NOTE: Should satisfy nSuperblockStartBlock > nBudgetPeymentsStartBlock
        consensus.nSuperblockCycle = 24; 				 // Superblocks can be issued hourly on testnet
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 500;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 100;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("00cef5fc5328768c82fd51ed1537c98f84e557df5093929a4bd4a88587552f64");
        consensus.powLimit = uint256S("00ffffffff000000000000000000000000000000000000000000000000000000");
        consensus.nPowAveragingWindow = 17;
        consensus.nPowMaxAdjustDown = 32;                               // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16;                                 // 16% adjustment up
        consensus.nPowTargetTimespan = 24 * 60 * 60;                    // Ulord: 1 day
        consensus.nPowTargetSpacing = 2.5 * 60;                         // Ulord: 2.5 minutes
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512;                // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; 			// nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601;                // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999;                  // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1518059142;                      // Thu Feb  8 11:05:42 CST 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout =   1549595142;                      // Thu Feb  8 11:05:42 CST 2019

        pchMessageStart[0] = 0xc2;
        pchMessageStart[1] = 0xe6;
        pchMessageStart[2] = 0xce;
        pchMessageStart[3] = 0xf3;
        vAlertPubKey = ParseHex("041c508f27e982c369486c0f1a42779208b3f5dc96c21a2af6004cb18d1529f42182425db1e1632dc6e73ff687592e148569022cee52b4b4eb10e8bb11bd927ec0");
        nDefaultPort = 19888;
        nMaxTipAge = 0x7fffffff; 		// allow mining on top of old blocks for testnet
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1518059142, 1940147270, 0x2000ffff, 1,  1 * COIN);
#ifdef GENESIS_GENERATION
	    arith_uint256 a("00ffffffff000000000000000000000000000000000000000000000000000000");
	    cout << "pow limit : " << a.GetCompact() << endl;
        findGenesis(&genesis, "testnet");
#endif
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00cef5fc5328768c82fd51ed1537c98f84e557df5093929a4bd4a88587552f64"));
        assert(genesis.hashMerkleRoot == uint256S("0x2b5ff31e4f2bccf51441d2f78849c2ca393daa187cede58373ccad8f1794b8d9"));

        vFixedSeeds.clear();
        vSeeds.clear();
	    vSeeds.push_back(CDNSSeedData("ulord.one",  "testnet-seed1.ulord.one"));    

        // Testnet Ulord addresses start with 'u'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,130);
        // Testnet Ulord script addresses start with 's'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,125);
        // Testnet private keys start with '9' or 'c'(as in Bitcoin)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,0xef);
        // Testnet Ulord BIP32 pubkeys start with 'tpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        // Testnet Ulord BIP32 prvkeys start with 'tprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
        // Testnet Ulord BIP44 coin type is '1' (All coin's testnet default)
        base58Prefixes[EXT_COIN_TYPE]  = boost::assign::list_of(0x80)(0x00)(0x00)(0x01).convert_to_container<std::vector<unsigned char> >();

        //vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 5*60;                          // fulfilled requests expire in 5 minutes
        strSporkPubKey = "046f78dcf911fbd61910136f7f0f8d90578f68d0b3ac973b5040fb7afb501b5939f39b108b0569dca71488f5bbf498d92e4d1194f6f941307ffd95f75e76869f0e";

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
	    (0, uint256S("00cef5fc5328768c82fd51ed1537c98f84e557df5093929a4bd4a88587552f64")),
            1518059142,     // * UNIX timestamp of last checkpoint block
            0,              // * total number of transactions between genesis and last checkpoint
                            //   (the tx=... number in the SetBestChain debug.log lines)
            0               // * estimated number of transactions per day after checkpoint
        };

	    // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = {
            "sNf43eLTrXdKKbDefUYiM6euWS5M1uwi9y"
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
        // reward setting
	    consensus.premine = i64(1e8 * COIN);                            // premine    
        consensus.genesisReward = i64(1 * COIN);                        // genesis
        consensus.minerReward4 = i64(112.966 * COIN);                   // miners
        consensus.minerReward5 = i64(535.103 * COIN);
        consensus.mnReward1 = i64(52.411 * COIN);                       // masternodes
        consensus.mnReward2 = i64(76.104 * COIN);
        consensus.mnReward5 = i64(535.103 * COIN);
        consensus.foundersReward = i64(4166666.667 * COIN);             // founders
        consensus.bdgetReward4 = i64(520833.333 * COIN);                // budget
        consensus.bdgetReward5 = i64(2083333.333 * COIN);
	    consensus.colleteral = i64(1e4 * COIN);                         // masternode colleteral
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
        consensus.BIP34Height = -1;                                     // BIP34 has not necessarily activated on regtest
        consensus.BIP34Hash = uint256();
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
	    consensus.nPowAveragingWindow = 17;
        consensus.nPowMaxAdjustDown = 0;                                // Turn off adjustment down
        consensus.nPowMaxAdjustUp = 0;                                  // Turn off adjustment up
        consensus.nPowTargetTimespan = 24 * 60 * 60;                    // Ulord: 1 day
        consensus.nPowTargetSpacing = 2.5 * 60;                         // Ulord: 2.5 minutes
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108;                 // 75% for testchains
        consensus.nMinerConfirmationWindow = 144;                       // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1000000000000ULL;

        pchMessageStart[0] = 0xf0;
        pchMessageStart[1] = 0xc5;
        pchMessageStart[2] = 0xbb;
        pchMessageStart[3] = 0xd0;
        nMaxTipAge = 6 * 60 * 60; // ~144 blocks behind -> 2 x fork detection time, was 24 * 60 * 60 in bitcoin
        nDefaultPort = 29888;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1517650354, 551787281, 0x200f0f0f, 1, 1 * COIN);
#ifdef GENESIS_GENERATION
        findGenesis(&genesis, "regtest");
#endif
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0158f211e2881c0e725fcc6ec25db2b72ad4a3f8f7830a516e9d6570e9527fd1"));
        assert(genesis.hashMerkleRoot == uint256S("2b5ff31e4f2bccf51441d2f78849c2ca393daa187cede58373ccad8f1794b8d9"));

        vFixedSeeds.clear();                                             //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();                                                  //! Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        nFulfilledRequestExpireTime = 5*60;                              // fulfilled requests expire in 5 minutes

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0158f211e2881c0e725fcc6ec25db2b72ad4a3f8f7830a516e9d6570e9527fd1")),
            0,
            0,
            0
        };
        // Regtest Ulord addresses start with 'y'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,140);
        // Regtest Ulord script addresses start with 'q'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,120);
        // Regtest private keys start with 'm'
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,0xef);
        // Regtest Ulord BIP32 pubkeys start with 'tpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        // Regtest Ulord BIP32 prvkeys start with 'tprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
        // Regtest Ulord BIP44 coin type is '1' (All coin's testnet default)
        base58Prefixes[EXT_COIN_TYPE]  = boost::assign::list_of(0x80)(0x00)(0x00)(0x01).convert_to_container<std::vector<unsigned char> >();

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = { "u2FwcEhFdNXuFMv1tcYwaBJtYVtMj8b1uTg" };
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

// Block height must be >1 and <last founders reward block height
// Index variable i ranges from 0 - (vFoundersRewardAddress.size()-1)
std::string CChainParams::GetFoundersRewardAddressAtHeight(int height) const
{
    assert(height > 1 && height < consensus.endOfFoundersReward());

    height /= consensus.nSuperblockCycle;
    size_t i = height % vFoundersRewardAddress.size();;
    return vFoundersRewardAddress[i];
}

// Block height must be >1 and <last founders reward block height
// The founders reward address is expected to be a multisig (P2SH) address
CScript CChainParams::GetFoundersRewardScriptAtHeight(int height) const
{
    assert(height > 1 && height < consensus.endOfFoundersReward());

    CBitcoinAddress address(GetFoundersRewardAddressAtHeight(height).c_str());
    assert(address.IsValid());
    CScript scriptPubKey = GetScriptForDestination(address.Get());
    return scriptPubKey;
}

std::string CChainParams::GetFoundersRewardAddressAtIndex(int i) const
{
    assert(i >= 0 && i < int(vFoundersRewardAddress.size()));
    return vFoundersRewardAddress[i];
}
