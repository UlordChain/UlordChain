// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "darksend.h"
#include "governance.h"
#include "governance-object.h"
#include "governance-vote.h"
#include "governance-classes.h"
#include "main.h"
#include "masternode.h"
#include "masternode-sync.h"
#include "masternodeman.h"
#include "netfulfilledman.h"
#include "util.h"

CGovernanceManager governance;

std::map<uint256, int64_t> mapAskedForGovernanceObject;

int nSubmittedFinalBudget;

const std::string CGovernanceManager::SERIALIZATION_VERSION_STRING = "CGovernanceManager-Version-8";

CGovernanceManager::CGovernanceManager()
    : pCurrentBlockIndex(NULL),
      nTimeLastDiff(0),
      nCachedBlockHeight(0),
      mapObjects(),
      mapSeenGovernanceObjects(),
      mapMasternodeOrphanObjects(),
      mapWatchdogObjects(),
      mapVoteToObject(MAX_CACHE_SIZE),
      mapInvalidVotes(MAX_CACHE_SIZE),
      mapOrphanVotes(MAX_CACHE_SIZE),
      mapLastMasternodeObject(),
      setRequestedObjects(),
      fRateChecksEnabled(true),
      cs()
{}

// Accessors for thread-safe access to maps
bool CGovernanceManager::HaveObjectForHash(uint256 nHash) {
    LOCK(cs);
    return (mapObjects.count(nHash) == 1);
}

bool CGovernanceManager::SerializeObjectForHash(uint256 nHash, CDataStream& ss)
{
    LOCK(cs);
    object_m_it it = mapObjects.find(nHash);
    if (it == mapObjects.end()) {
        return false;
    }
    ss << it->second;
    return true;
}

bool CGovernanceManager::HaveVoteForHash(uint256 nHash)
{
    LOCK(cs);

    CGovernanceObject* pGovobj = NULL;
    if(!mapVoteToObject.Get(nHash,pGovobj)) {
        return false;
    }

    if(!pGovobj->GetVoteFile().HasVote(nHash)) {
        return false;
    }
    return true;
}

bool CGovernanceManager::SerializeVoteForHash(uint256 nHash, CDataStream& ss)
{
    LOCK(cs);

    CGovernanceObject* pGovobj = NULL;
    if(!mapVoteToObject.Get(nHash,pGovobj)) {
        return false;
    }

    CGovernanceVote vote;
    if(!pGovobj->GetVoteFile().GetVote(nHash, vote)) {
        return false;
    }

    ss << vote;
    return true;
}

void CGovernanceManager::AddSeenGovernanceObject(uint256 nHash, int status)
{
    LOCK(cs);
    mapSeenGovernanceObjects[nHash] = status;
}

void CGovernanceManager::ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv)
{
    // lite mode is not supported
    if(fLiteMode) return;
    if(!masternodeSync.IsBlockchainSynced()) return;

    if(pfrom->nVersion < MIN_GOVERNANCE_PEER_PROTO_VERSION) return;

    // ANOTHER USER IS ASKING US TO HELP THEM SYNC GOVERNANCE OBJECT DATA
    if (strCommand == NetMsgType::MNGOVERNANCESYNC)
    {

        // Ignore such requests until we are fully synced.
        // We could start processing this after masternode list is synced
        // but this is a heavy one so it's better to finish sync first.
        if (!masternodeSync.IsSynced()) return;

        uint256 nProp;
        CBloomFilter filter;

        vRecv >> nProp;

        if(pfrom->nVersion >= GOVERNANCE_FILTER_PROTO_VERSION) {
            vRecv >> filter;
            filter.UpdateEmptyFull();
        }
        else {
            filter.clear();
        }

        if(nProp == uint256()) {
            if(netfulfilledman.HasFulfilledRequest(pfrom->addr, NetMsgType::MNGOVERNANCESYNC)) {
                // Asking for the whole list multiple times in a short period of time is no good
                LogPrint("gobject", "MNGOVERNANCESYNC -- peer already asked me for the list\n");
                Misbehaving(pfrom->GetId(), 20);
                return;
            }
            netfulfilledman.AddFulfilledRequest(pfrom->addr, NetMsgType::MNGOVERNANCESYNC);
        }

        Sync(pfrom, nProp, filter);
        LogPrint("gobject", "MNGOVERNANCESYNC -- syncing governance objects to our peer at %s\n", pfrom->addr.ToString());

    }

    // A NEW GOVERNANCE OBJECT HAS ARRIVED
    else if (strCommand == NetMsgType::MNGOVERNANCEOBJECT)

    {
        // MAKE SURE WE HAVE A VALID REFERENCE TO THE TIP BEFORE CONTINUING

        if(!pCurrentBlockIndex) {
            LogPrintf("MNGOVERNANCEOBJECT -- pCurrentBlockIndex is NULL\n");
            return;
        }

        if(!masternodeSync.IsMasternodeListSynced()) {
            LogPrint("gobject", "MNGOVERNANCEOBJECT -- masternode list not synced\n");
            return;
        }

        CGovernanceObject govobj;
        vRecv >> govobj;

        uint256 nHash = govobj.GetHash();
        std::string strHash = nHash.ToString();

        pfrom->setAskFor.erase(nHash);

        LogPrint("gobject", "MNGOVERNANCEOBJECT -- Received object: %s\n", strHash);

        if(!AcceptObjectMessage(nHash)) {
            LogPrintf("MNGOVERNANCEOBJECT -- Received unrequested object: %s\n", strHash);
            return;
        }

        LOCK2(cs_main, cs);

        if(mapSeenGovernanceObjects.count(nHash)) {
            // TODO - print error code? what if it's GOVOBJ_ERROR_IMMATURE?
            LogPrint("gobject", "MNGOVERNANCEOBJECT -- Received already seen object: %s\n", strHash);
            return;
        }

        bool fRateCheckBypassed = false;
        if(!MasternodeRateCheck(govobj, true, false, fRateCheckBypassed)) {
            LogPrintf("MNGOVERNANCEOBJECT -- masternode rate check failed - %s - (current block height %d) \n", strHash, nCachedBlockHeight);
            return;
        }

        std::string strError = "";
        // CHECK OBJECT AGAINST LOCAL BLOCKCHAIN

        bool fMasternodeMissing = false;
        bool fIsValid = govobj.IsValidLocally(strError, fMasternodeMissing, true);

        if(fMasternodeMissing) {
            mapMasternodeOrphanObjects.insert(std::make_pair(nHash, object_time_pair_t(govobj, GetAdjustedTime() + GOVERNANCE_ORPHAN_EXPIRATION_TIME)));
            LogPrintf("MNGOVERNANCEOBJECT -- Missing masternode for: %s, strError = %s\n", strHash, strError);
            // fIsValid must also be false here so we will return early in the next if block
        }
        if(!fIsValid) {
            mapSeenGovernanceObjects.insert(std::make_pair(nHash, SEEN_OBJECT_ERROR_INVALID));
            LogPrintf("MNGOVERNANCEOBJECT -- Governance object is invalid - %s\n", strError);
            return;
        }

        if(fRateCheckBypassed) {
            if(!MasternodeRateCheck(govobj, true, true, fRateCheckBypassed)) {
                LogPrintf("MNGOVERNANCEOBJECT -- masternode rate check failed (after signature verification) - %s - (current block height %d) \n", strHash, nCachedBlockHeight);
                return;
            }
        }

        // UPDATE CACHED VARIABLES FOR THIS OBJECT AND ADD IT TO OUR MANANGED DATA

        govobj.UpdateSentinelVariables(); //this sets local vars in object

        if(AddGovernanceObject(govobj))
        {
            LogPrintf("MNGOVERNANCEOBJECT -- %s new\n", strHash);
            govobj.Relay();
        }

        // UPDATE THAT WE'VE SEEN THIS OBJECT
        mapSeenGovernanceObjects.insert(std::make_pair(nHash, SEEN_OBJECT_IS_VALID));
        masternodeSync.AddedGovernanceItem();


        // WE MIGHT HAVE PENDING/ORPHAN VOTES FOR THIS OBJECT

        CGovernanceException exception;
        CheckOrphanVotes(govobj, exception);
    }

    // A NEW GOVERNANCE OBJECT VOTE HAS ARRIVED
    else if (strCommand == NetMsgType::MNGOVERNANCEOBJECTVOTE)
    {
        // Ignore such messages until masternode list is synced
        if(!masternodeSync.IsMasternodeListSynced()) {
            LogPrint("gobject", "MNGOVERNANCEOBJECTVOTE -- masternode list not synced\n");
            return;
        }

        CGovernanceVote vote;
        vRecv >> vote;

        LogPrint("gobject", "MNGOVERNANCEOBJECTVOTE -- Received vote: %s\n", vote.ToString());

        uint256 nHash = vote.GetHash();
        std::string strHash = nHash.ToString();

        pfrom->setAskFor.erase(nHash);

        if(!AcceptVoteMessage(nHash)) {
            LogPrint("gobject", "MNGOVERNANCEOBJECTVOTE -- Received unrequested vote object: %s, hash: %s, peer = %d\n",
                      vote.ToString(), strHash, pfrom->GetId());
            return;
        }

        CGovernanceException exception;
        if(ProcessVote(pfrom, vote, exception)) {
            LogPrint("gobject", "MNGOVERNANCEOBJECTVOTE -- %s new\n", strHash);
            masternodeSync.AddedGovernanceItem();
            vote.Relay();
        }
        else {
            LogPrint("gobject", "MNGOVERNANCEOBJECTVOTE -- Rejected vote, error = %s\n", exception.what());
            if((exception.GetNodePenalty() != 0) && masternodeSync.IsSynced()) {
                Misbehaving(pfrom->GetId(), exception.GetNodePenalty());
            }
            return;
        }

    }
}

void CGovernanceManager::CheckOrphanVotes(CGovernanceObject& govobj, CGovernanceException& exception)
{
    uint256 nHash = govobj.GetHash();
    std::vector<vote_time_pair_t> vecVotePairs;
    mapOrphanVotes.GetAll(nHash, vecVotePairs);

    fRateChecksEnabled = false;
    int64_t nNow = GetAdjustedTime();
    for(size_t i = 0; i < vecVotePairs.size(); ++i) {
        bool fRemove = false;
        vote_time_pair_t& pairVote = vecVotePairs[i];
        CGovernanceVote& vote = pairVote.first;
        CGovernanceException exception;
        if(pairVote.second < nNow) {
            fRemove = true;
        }
        else if(govobj.ProcessVote(NULL, vote, exception)) {
            vote.Relay();
            fRemove = true;
        }
        if(fRemove) {
            mapOrphanVotes.Erase(nHash, pairVote);
        }
    }
    fRateChecksEnabled = true;
}

bool CGovernanceManager::AddGovernanceObject(CGovernanceObject& govobj)
{
    LOCK2(cs_main, cs);
    std::string strError = "";

    DBG( cout << "CGovernanceManager::AddGovernanceObject START" << endl; );

    uint256 nHash = govobj.GetHash();

    // MAKE SURE THIS OBJECT IS OK

    if(!govobj.IsValidLocally(strError, true)) {
        LogPrintf("CGovernanceManager::AddGovernanceObject -- invalid governance object - %s - (nCachedBlockHeight %d) \n", strError, nCachedBlockHeight);
        return false;
    }

    // IF WE HAVE THIS OBJECT ALREADY, WE DON'T WANT ANOTHER COPY

    if(mapObjects.count(nHash)) {
        LogPrintf("CGovernanceManager::AddGovernanceObject -- already have governance object %s\n", nHash.ToString());
        return false;
    }

    LogPrint("gobject", "CGovernanceManager::AddGovernanceObject -- Adding object: hash = %s, type = %d\n", nHash.ToString(), govobj.GetObjectType()); 

    // INSERT INTO OUR GOVERNANCE OBJECT MEMORY
    mapObjects.insert(std::make_pair(nHash, govobj));

    // SHOULD WE ADD THIS OBJECT TO ANY OTHER MANANGERS?

    DBG( cout << "CGovernanceManager::AddGovernanceObject Before trigger block, strData = "
              << govobj.GetDataAsString()
              << ", nObjectType = " << govobj.nObjectType
              << endl; );

    switch(govobj.nObjectType) {
    case GOVERNANCE_OBJECT_TRIGGER:
        DBG( cout << "CGovernanceManager::AddGovernanceObject Before AddNewTrigger" << endl; );
        triggerman.AddNewTrigger(nHash);
        DBG( cout << "CGovernanceManager::AddGovernanceObject After AddNewTrigger" << endl; );
        break;
    case GOVERNANCE_OBJECT_WATCHDOG:
        mapWatchdogObjects[nHash] = GetAdjustedTime() + GOVERNANCE_WATCHDOG_EXPIRATION_TIME;
        LogPrint("gobject", "CGovernanceManager::AddGovernanceObject -- Added watchdog to map: hash = %s\n", nHash.ToString()); 
        break;
    default:
        break;
    }

    DBG( cout << "CGovernanceManager::AddGovernanceObject END" << endl; );

    return true;
}

void CGovernanceManager::UpdateCachesAndClean()
{
    LogPrint("gobject", "CGovernanceManager::UpdateCachesAndClean\n");

    std::vector<uint256> vecDirtyHashes = mnodeman.GetAndClearDirtyGovernanceObjectHashes();

    LOCK(cs);

    // Flag expired watchdogs for removal
    int64_t nNow = GetAdjustedTime();
    LogPrint("gobject", "CGovernanceManager::UpdateCachesAndClean -- Number watchdogs in map: %d, current time = %d\n", mapWatchdogObjects.size(), nNow);
    if(mapWatchdogObjects.size() > 1) {
        hash_time_m_it it = mapWatchdogObjects.begin();
        while(it != mapWatchdogObjects.end()) {
            LogPrint("gobject", "CGovernanceManager::UpdateCachesAndClean -- Checking watchdog: %s, expiration time = %d\n", it->first.ToString(), it->second);
            if(it->second < nNow) {
                LogPrint("gobject", "CGovernanceManager::UpdateCachesAndClean -- Attempting to expire watchdog: %s, expiration time = %d\n", it->first.ToString(), it->second);
                object_m_it it2 = mapObjects.find(it->first);
                if(it2 != mapObjects.end()) {
                    LogPrint("gobject", "CGovernanceManager::UpdateCachesAndClean -- Expiring watchdog: %s, expiration time = %d\n", it->first.ToString(), it->second);
                    it2->second.fExpired = true;
                    if(it2->second.nDeletionTime == 0) {
                        it2->second.nDeletionTime = nNow;
                    }
                }
                mapWatchdogObjects.erase(it++);
            }
            else {
                ++it;
            }
        }
    }

    for(size_t i = 0; i < vecDirtyHashes.size(); ++i) {
        object_m_it it = mapObjects.find(vecDirtyHashes[i]);
        if(it == mapObjects.end()) {
            continue;
        }
        it->second.ClearMasternodeVotes();
        it->second.fDirtyCache = true;
    }

    // DOUBLE CHECK THAT WE HAVE A VALID POINTER TO TIP

    if(!pCurrentBlockIndex) return;

    fRateChecksEnabled = false;

    LogPrint("gobject", "CGovernanceManager::UpdateCachesAndClean -- After pCurrentBlockIndex (not NULL)\n");

    // UPDATE CACHE FOR EACH OBJECT THAT IS FLAGGED DIRTYCACHE=TRUE

    object_m_it it = mapObjects.begin();

    // Clean up any expired or invalid triggers
    triggerman.CleanAndRemove();

    while(it != mapObjects.end())
    {
        CGovernanceObject* pObj = &((*it).second);

        if(!pObj) {
            ++it;
            continue;
        }

        std::string strHash = pObj->GetHash().ToString();

        // IF CACHE IS NOT DIRTY, WHY DO THIS?
        if(pObj->IsSetDirtyCache()) {
            // UPDATE LOCAL VALIDITY AGAINST CRYPTO DATA
            pObj->UpdateLocalValidity();

            // UPDATE SENTINEL SIGNALING VARIABLES
            pObj->UpdateSentinelVariables();
        }

        // IF DELETE=TRUE, THEN CLEAN THE MESS UP!

        int64_t nTimeSinceDeletion = GetAdjustedTime() - pObj->GetDeletionTime();

        LogPrint("gobject", "CGovernanceManager::UpdateCachesAndClean -- Checking object for deletion: %s, deletion time = %d, time since deletion = %d, delete flag = %d, expired flag = %d\n",
                 strHash, pObj->GetDeletionTime(), nTimeSinceDeletion, pObj->IsSetCachedDelete(), pObj->IsSetExpired());

        if((pObj->IsSetCachedDelete() || pObj->IsSetExpired()) &&
           (nTimeSinceDeletion >= GOVERNANCE_DELETION_DELAY)) {
            LogPrintf("CGovernanceManager::UpdateCachesAndClean -- erase obj %s\n", (*it).first.ToString());
            mnodeman.RemoveGovernanceObject(pObj->GetHash());

            // Remove vote references
            const object_ref_cache_t::list_t& listItems = mapVoteToObject.GetItemList();
            object_ref_cache_t::list_cit lit = listItems.begin();
            while(lit != listItems.end()) {
                if(lit->value == pObj) {
                    uint256 nKey = lit->key;
                    ++lit;
                    mapVoteToObject.Erase(nKey);
                }
                else {
                    ++lit;
                }
            }

            mapObjects.erase(it++);
        } else {
            ++it;
        }
    }

    fRateChecksEnabled = true;
}

CGovernanceObject *CGovernanceManager::FindGovernanceObject(const uint256& nHash)
{
    LOCK(cs);

    if(mapObjects.count(nHash))
        return &mapObjects[nHash];

    return NULL;
}

std::vector<CGovernanceVote> CGovernanceManager::GetMatchingVotes(const uint256& nParentHash)
{
    LOCK(cs);
    std::vector<CGovernanceVote> vecResult;

    object_m_it it = mapObjects.find(nParentHash);
    if(it == mapObjects.end()) {
        return vecResult;
    }
    CGovernanceObject& govobj = it->second;

    return govobj.GetVoteFile().GetVotes();
}

std::vector<CGovernanceVote> CGovernanceManager::GetCurrentVotes(const uint256& nParentHash, const CTxIn& mnCollateralOutpointFilter)
{
    LOCK(cs);
    std::vector<CGovernanceVote> vecResult;

    // Find the governance object or short-circuit.
    object_m_it it = mapObjects.find(nParentHash);
    if(it == mapObjects.end()) return vecResult;
    CGovernanceObject& govobj = it->second;

    // Compile a list of Masternode collateral outpoints for which to get votes
    std::vector<CTxIn> vecMNTxIn;
    if (mnCollateralOutpointFilter == CTxIn()) {
        std::vector<CMasternode> mnlist = mnodeman.GetFullMasternodeVector();
        for (std::vector<CMasternode>::iterator it = mnlist.begin(); it != mnlist.end(); ++it)
        {
            vecMNTxIn.push_back(it->vin);
        }
    }
    else {
        vecMNTxIn.push_back(mnCollateralOutpointFilter);
    }

    // Loop thru each MN collateral outpoint and get the votes for the `nParentHash` governance object
    for (std::vector<CTxIn>::iterator it = vecMNTxIn.begin(); it != vecMNTxIn.end(); ++it)
    {
        CTxIn &mnCollateralOutpoint = *it;

        // get a vote_rec_t from the govobj
        vote_rec_t voteRecord;
        if (!govobj.GetCurrentMNVotes(mnCollateralOutpoint, voteRecord)) continue;

        for (vote_instance_m_it it3 = voteRecord.mapInstances.begin(); it3 != voteRecord.mapInstances.end(); ++it3) {
            int signal = (it3->first);
            int outcome = ((it3->second).eOutcome);
            int64_t nTime = ((it3->second).nTime);

            CGovernanceVote vote = CGovernanceVote(mnCollateralOutpoint, nParentHash, (vote_signal_enum_t)signal, (vote_outcome_enum_t)outcome);
            vote.SetTime(nTime);

            vecResult.push_back(vote);
        }
    }

    return vecResult;
}

std::vector<CGovernanceObject*> CGovernanceManager::GetAllNewerThan(int64_t nMoreThanTime)
{
    LOCK(cs);

    std::vector<CGovernanceObject*> vGovObjs;

    object_m_it it = mapObjects.begin();
    while(it != mapObjects.end())
    {
        // IF THIS OBJECT IS OLDER THAN TIME, CONTINUE

        if((*it).second.GetCreationTime() < nMoreThanTime) {
            ++it;
            continue;
        }

        // ADD GOVERNANCE OBJECT TO LIST

        CGovernanceObject* pGovObj = &((*it).second);
        vGovObjs.push_back(pGovObj);

        // NEXT

        ++it;
    }

    return vGovObjs;
}

//
// Sort by votes, if there's a tie sort by their feeHash TX
//
struct sortProposalsByVotes {
    bool operator()(const std::pair<CGovernanceObject*, int> &left, const std::pair<CGovernanceObject*, int> &right) {
        if (left.second != right.second)
            return (left.second > right.second);
        return (UintToArith256(left.first->GetCollateralHash()) > UintToArith256(right.first->GetCollateralHash()));
    }
};

void CGovernanceManager::NewBlock()
{
    // IF WE'RE NOT SYNCED, EXIT
    if(!masternodeSync.IsSynced()) return;

    if(!pCurrentBlockIndex) return;
    LOCK(cs);


    // CHECK OBJECTS WE'VE ASKED FOR, REMOVE OLD ENTRIES

    std::map<uint256, int64_t>::iterator it = mapAskedForGovernanceObject.begin();
    while(it != mapAskedForGovernanceObject.end()) {
        if((*it).second > GetTime() - (60*60*24)) {
            ++it;
        } else {
            mapAskedForGovernanceObject.erase(it++);
        }
    }

    // CHECK AND REMOVE - REPROCESS GOVERNANCE OBJECTS

    UpdateCachesAndClean();
}

bool CGovernanceManager::ConfirmInventoryRequest(const CInv& inv)
{
    LOCK(cs);

    LogPrint("gobject", "CGovernanceManager::ConfirmInventoryRequest inv = %s\n", inv.ToString());

    // First check if we've already recorded this object
    switch(inv.type) {
    case MSG_GOVERNANCE_OBJECT:
    {
        object_m_it it = mapObjects.find(inv.hash);
        if(it != mapObjects.end()) {
            LogPrint("gobject", "CGovernanceManager::ConfirmInventoryRequest already have governance object, returning false\n");
            return false;
        }
    }
    break;
    case MSG_GOVERNANCE_OBJECT_VOTE:
    {
        if(mapVoteToObject.HasKey(inv.hash)) {
            LogPrint("gobject", "CGovernanceManager::ConfirmInventoryRequest already have governance vote, returning false\n");
            return false;
        }
    }
    break;
    default:
        LogPrint("gobject", "CGovernanceManager::ConfirmInventoryRequest unknown type, returning false\n");
        return false;
    }


    hash_s_t* setHash = NULL;
    switch(inv.type) {
    case MSG_GOVERNANCE_OBJECT:
        setHash = &setRequestedObjects;
        break;
    case MSG_GOVERNANCE_OBJECT_VOTE:
        setHash = &setRequestedVotes;
        break;
    default:
        return false;
    }

    hash_s_cit it = setHash->find(inv.hash);
    if(it == setHash->end()) {
        setHash->insert(inv.hash);
        LogPrint("gobject", "CGovernanceManager::ConfirmInventoryRequest added inv to requested set\n");
    }

    // Keep sync alive
    masternodeSync.AddedGovernanceItem();

    LogPrint("gobject", "CGovernanceManager::ConfirmInventoryRequest reached end, returning true\n");
    return true;
}

void CGovernanceManager::Sync(CNode* pfrom, const uint256& nProp, const CBloomFilter& filter)
{

    /*
        This code checks each of the hash maps for all known budget proposals and finalized budget proposals, then checks them against the
        budget object to see if they're OK. If all checks pass, we'll send it to the peer.
    */

    int nObjCount = 0;
    int nVoteCount = 0;

    // SYNC GOVERNANCE OBJECTS WITH OTHER CLIENT

    LogPrint("gobject", "CGovernanceManager::Sync -- syncing to peer=%d, nProp = %s\n", pfrom->id, nProp.ToString());

    {
        LOCK2(cs_main, cs);

        if(nProp == uint256()) {
            // all valid objects, no votes
            for(object_m_it it = mapObjects.begin(); it != mapObjects.end(); ++it) {
                CGovernanceObject& govobj = it->second;
                std::string strHash = it->first.ToString();

                LogPrint("gobject", "CGovernanceManager::Sync -- attempting to sync govobj: %s, peer=%d\n", strHash, pfrom->id);

                if(govobj.IsSetCachedDelete()) {
                    LogPrintf("CGovernanceManager::Sync -- not syncing deleted govobj: %s, peer=%d\n",
                              strHash, pfrom->id);
                    continue;
                }

                // Push the inventory budget proposal message over to the other client
                LogPrint("gobject", "CGovernanceManager::Sync -- syncing govobj: %s, peer=%d\n", strHash, pfrom->id);
                pfrom->PushInventory(CInv(MSG_GOVERNANCE_OBJECT, it->first));
                ++nObjCount;
            }
        } else {
            // single valid object and its valid votes
            object_m_it it = mapObjects.find(nProp);
            if(it == mapObjects.end()) {
                LogPrint("gobject", "CGovernanceManager::Sync -- no matching object for hash %s, peer=%d\n", nProp.ToString(), pfrom->id);
                return;
            }
            CGovernanceObject& govobj = it->second;
            std::string strHash = it->first.ToString();

            LogPrint("gobject", "CGovernanceManager::Sync -- attempting to sync govobj: %s, peer=%d\n", strHash, pfrom->id);

            if(govobj.IsSetCachedDelete()) {
                LogPrintf("CGovernanceManager::Sync -- not syncing deleted govobj: %s, peer=%d\n",
                          strHash, pfrom->id);
                return;
            }

            // Push the inventory budget proposal message over to the other client
            LogPrint("gobject", "CGovernanceManager::Sync -- syncing govobj: %s, peer=%d\n", strHash, pfrom->id);
            pfrom->PushInventory(CInv(MSG_GOVERNANCE_OBJECT, it->first));
            ++nObjCount;

            std::vector<CGovernanceVote> vecVotes = govobj.GetVoteFile().GetVotes();
            for(size_t i = 0; i < vecVotes.size(); ++i) {
                if(!vecVotes[i].IsValid(true)) {
                    continue;
                }
                if(filter.contains(vecVotes[i].GetHash())) {
                    continue;
                }
                pfrom->PushInventory(CInv(MSG_GOVERNANCE_OBJECT_VOTE, vecVotes[i].GetHash()));
                ++nVoteCount;
            }
        }
    }

    pfrom->PushMessage(NetMsgType::SYNCSTATUSCOUNT, MASTERNODE_SYNC_GOVOBJ, nObjCount);
    pfrom->PushMessage(NetMsgType::SYNCSTATUSCOUNT, MASTERNODE_SYNC_GOVOBJ_VOTE, nVoteCount);
    LogPrintf("CGovernanceManager::Sync -- sent %d objects and %d votes to peer=%d\n", nObjCount, nVoteCount, pfrom->id);
}

bool CGovernanceManager::MasternodeRateCheck(const CGovernanceObject& govobj, bool fUpdateLast)
{
    bool fRateCheckBypassed = false;
    return MasternodeRateCheck(govobj, fUpdateLast, true, fRateCheckBypassed);
}

bool CGovernanceManager::MasternodeRateCheck(const CGovernanceObject& govobj, bool fUpdateLast, bool fForce, bool& fRateCheckBypassed)
{
    LOCK(cs);

    fRateCheckBypassed = false;

    if(!masternodeSync.IsSynced()) {
        return true;
    }

    if(!fRateChecksEnabled) {
        return true;
    }

    int nObjectType = govobj.GetObjectType();
    if((nObjectType != GOVERNANCE_OBJECT_TRIGGER) && (nObjectType != GOVERNANCE_OBJECT_WATCHDOG)) {
        return true;
    }

    int64_t nTimestamp = govobj.GetCreationTime();
    int64_t nNow = GetTime();
    int64_t nSuperblockCycleSeconds = Params().GetConsensus().nSuperblockCycle * Params().GetConsensus().nPowTargetSpacing;

    const CTxIn& vin = govobj.GetMasternodeVin();

    txout_m_it it  = mapLastMasternodeObject.find(vin.prevout);

    if(it == mapLastMasternodeObject.end()) {
        if(fUpdateLast) {
            it = mapLastMasternodeObject.insert(txout_m_t::value_type(vin.prevout, last_object_rec(true))).first;
            switch(nObjectType) {
            case GOVERNANCE_OBJECT_TRIGGER:
                it->second.triggerBuffer.AddTimestamp(nTimestamp);
                break;
            case GOVERNANCE_OBJECT_WATCHDOG:
                it->second.watchdogBuffer.AddTimestamp(nTimestamp);
                break;
            default:
                break;
            }
        }
        return true;
    }

    if(it->second.fStatusOK && !fForce) {
        fRateCheckBypassed = true;
        return true;
    }

    std::string strHash = govobj.GetHash().ToString();

    if(nTimestamp < nNow - 2 * nSuperblockCycleSeconds) {
        LogPrintf("CGovernanceManager::MasternodeRateCheck -- object %s rejected due to too old timestamp, masternode vin = %s, timestamp = %d, current time = %d\n",
                 strHash, vin.prevout.ToStringShort(), nTimestamp, nNow);
        return false;
    }

    if(nTimestamp > nNow + 60*60) {
        LogPrintf("CGovernanceManager::MasternodeRateCheck -- object %s rejected due to too new (future) timestamp, masternode vin = %s, timestamp = %d, current time = %d\n",
                 strHash, vin.prevout.ToStringShort(), nTimestamp, nNow);
        return false;
    }
    
    double dMaxRate = 1.1 / nSuperblockCycleSeconds;
    double dRate = 0.0;
    CRateCheckBuffer buffer;
    switch(nObjectType) {
    case GOVERNANCE_OBJECT_TRIGGER:
        // Allow 1 trigger per mn per cycle, with a small fudge factor
        dMaxRate = 2 * 1.1 / double(nSuperblockCycleSeconds);
        buffer = it->second.triggerBuffer;
        buffer.AddTimestamp(nTimestamp);
        dRate = buffer.GetRate();
        if(fUpdateLast) {
            it->second.triggerBuffer.AddTimestamp(nTimestamp);
        }
        break;
    case GOVERNANCE_OBJECT_WATCHDOG:
        dMaxRate = 2 * 1.1 / 3600.;
        buffer = it->second.watchdogBuffer;
        buffer.AddTimestamp(nTimestamp);
        dRate = buffer.GetRate();
        if(fUpdateLast) {
            it->second.watchdogBuffer.AddTimestamp(nTimestamp);
        }
        break;
    default:
        break;
    }

    if(dRate < dMaxRate) {
        if(fUpdateLast) {
            it->second.fStatusOK = true;
        }
        return true;
    }
    else {
        if(fUpdateLast) {
            it->second.fStatusOK = false;
        }
    }

    LogPrintf("CGovernanceManager::MasternodeRateCheck -- Rate too high: object hash = %s, masternode vin = %s, object timestamp = %d, rate = %f, max rate = %f\n",
              strHash, vin.prevout.ToStringShort(), nTimestamp, dRate, dMaxRate);
    return false;
}

bool CGovernanceManager::ProcessVote(CNode* pfrom, const CGovernanceVote& vote, CGovernanceException& exception)
{
    LOCK(cs);
    uint256 nHashVote = vote.GetHash();
    if(mapInvalidVotes.HasKey(nHashVote)) {
        std::ostringstream ostr;
        ostr << "CGovernanceManager::ProcessVote -- Old invalid vote "
                << ", MN outpoint = " << vote.GetVinMasternode().prevout.ToStringShort()
                << ", governance object hash = " << vote.GetParentHash().ToString() << "\n";
        LogPrintf(ostr.str().c_str());
        exception = CGovernanceException(ostr.str(), GOVERNANCE_EXCEPTION_PERMANENT_ERROR, 20);
        return false;
    }

    uint256 nHashGovobj = vote.GetParentHash();
    object_m_it it = mapObjects.find(nHashGovobj);
    if(it == mapObjects.end()) {
        std::ostringstream ostr;
        ostr << "CGovernanceManager::ProcessVote -- Unknown parent object "
             << ", MN outpoint = " << vote.GetVinMasternode().prevout.ToStringShort()
             << ", governance object hash = " << vote.GetParentHash().ToString() << "\n";
        exception = CGovernanceException(ostr.str(), GOVERNANCE_EXCEPTION_WARNING);
        if(mapOrphanVotes.Insert(nHashGovobj, vote_time_pair_t(vote, GetAdjustedTime() + GOVERNANCE_ORPHAN_EXPIRATION_TIME))) {
            RequestGovernanceObject(pfrom, nHashGovobj);
            LogPrintf(ostr.str().c_str());
        }
        else {
            LogPrint("gobject", ostr.str().c_str());
        }
        return false;
    }

    CGovernanceObject& govobj = it->second;
    bool fOk = govobj.ProcessVote(pfrom, vote, exception);
    if(fOk) {
        mapVoteToObject.Insert(nHashVote, &govobj);

        if(govobj.GetObjectType() == GOVERNANCE_OBJECT_WATCHDOG) {
            mnodeman.UpdateWatchdogVoteTime(vote.GetVinMasternode());
        }
    }
    return fOk;
}

void CGovernanceManager::CheckMasternodeOrphanVotes()
{
    LOCK2(cs_main, cs);
    fRateChecksEnabled = false;
    for(object_m_it it = mapObjects.begin(); it != mapObjects.end(); ++it) {
        it->second.CheckOrphanVotes();
    }
    fRateChecksEnabled = true;
}

void CGovernanceManager::CheckMasternodeOrphanObjects()
{
    LOCK2(cs_main, cs);
    int64_t nNow = GetAdjustedTime();
    fRateChecksEnabled = false;
    object_time_m_it it = mapMasternodeOrphanObjects.begin();
    while(it != mapMasternodeOrphanObjects.end()) {
        object_time_pair_t& pair = it->second;
        CGovernanceObject& govobj = pair.first;

        if(pair.second < nNow) {
            mapMasternodeOrphanObjects.erase(it++);
            continue;
        }

        string strError;
        bool fMasternodeMissing = false;
        bool fIsValid = govobj.IsValidLocally(strError, fMasternodeMissing, true);
        if(!fIsValid) {
            if(!fMasternodeMissing) {
                mapMasternodeOrphanObjects.erase(it++);
            }
            else {
                ++it;
            }
            continue;
        }

        if(AddGovernanceObject(govobj)) {
            LogPrintf("CGovernanceManager::CheckMasternodeOrphanObjects -- %s new\n", govobj.GetHash().ToString());
            govobj.Relay();
            mapMasternodeOrphanObjects.erase(it++);
        }
        else {
            ++it;
        }
    }
    fRateChecksEnabled = true;
}

void CGovernanceManager::RequestGovernanceObject(CNode* pfrom, const uint256& nHash, bool fUseFilter)
{
    if(!pfrom) {
        return;
    }

    if(pfrom->nVersion < GOVERNANCE_FILTER_PROTO_VERSION) {
        pfrom->PushMessage(NetMsgType::MNGOVERNANCESYNC, nHash);
        return;
    }

    CBloomFilter filter;
    filter.clear();

    if(fUseFilter) {
        CGovernanceObject* pObj = FindGovernanceObject(nHash);

        if(pObj) {
            filter = CBloomFilter(Params().GetConsensus().nGovernanceFilterElements, GOVERNANCE_FILTER_FP_RATE, GetRandInt(999999), BLOOM_UPDATE_ALL);
            std::vector<CGovernanceVote> vecVotes = pObj->GetVoteFile().GetVotes();
            for(size_t i = 0; i < vecVotes.size(); ++i) {
                filter.insert(vecVotes[i].GetHash());
            }
        }
    }

    pfrom->PushMessage(NetMsgType::MNGOVERNANCESYNC, nHash, filter);
}

void CGovernanceManager::RequestGovernanceObjectVotes(CNode* pnode)
{
    if(pnode->nVersion < MIN_GOVERNANCE_PEER_PROTO_VERSION) return;
    std::vector<CNode*> vNodesCopy;
    vNodesCopy.push_back(pnode);
    RequestGovernanceObjectVotes(vNodesCopy);
}

void CGovernanceManager::RequestGovernanceObjectVotes(const std::vector<CNode*>& vNodesCopy)
{
    static std::map<uint256, std::map<CService, int64_t> > mapAskedRecently;

    if(vNodesCopy.empty()) return;

    LOCK2(cs_main, cs);

    int64_t nNow = GetTime();
    int nTimeout = 60 * 60;
    size_t nPeersPerHashMax = 3;

    // This should help us to get some idea about an impact this can bring once deployed on mainnet.
    // Testnet is ~40 times smaller in masternode count, but only ~1000 masternodes usually vote,
    // so 1 obj on mainnet == ~10 objs or ~1000 votes on testnet. However we want to test a higher
    // number of votes to make sure it's robust enough, so aim at 2000 votes per masternode per request.
    // On mainnet nMaxObjRequestsPerNode is always set to 1.
    int nMaxObjRequestsPerNode = 1;
    size_t nProjectedVotes = 2000;
    if(Params().NetworkIDString() != CBaseChainParams::MAIN) {
        nMaxObjRequestsPerNode = std::max(1, int(nProjectedVotes / std::max(1, mnodeman.size())));
    }

    std::vector<CGovernanceObject*> vpGovObjsTmp;
    std::vector<CGovernanceObject*> vpGovObjsTriggersTmp;

    for(object_m_it it = mapObjects.begin(); it != mapObjects.end(); ++it) {
        if(mapAskedRecently.count(it->first)) {
            std::map<CService, int64_t>::iterator it1 = mapAskedRecently[it->first].begin();
            while(it1 != mapAskedRecently[it->first].end()) {
                if(it1->second < nNow) {
                    mapAskedRecently[it->first].erase(it1++);
                } else {
                    ++it1;
                }
            }
            if(mapAskedRecently[it->first].size() >= nPeersPerHashMax) continue;
        }
        if(it->second.nObjectType == GOVERNANCE_OBJECT_TRIGGER) {
            vpGovObjsTriggersTmp.push_back(&(it->second));
        } else {
            vpGovObjsTmp.push_back(&(it->second));
        }
    }

    LogPrint("governance", "CGovernanceManager::RequestGovernanceObjectVotes -- start: vpGovObjsTriggersTmp %d vpGovObjsTmp %d mapAskedRecently %d\n",
                vpGovObjsTriggersTmp.size(), vpGovObjsTmp.size(), mapAskedRecently.size());

    InsecureRand insecureRand;
    // shuffle pointers
    std::random_shuffle(vpGovObjsTriggersTmp.begin(), vpGovObjsTriggersTmp.end(), insecureRand);
    std::random_shuffle(vpGovObjsTmp.begin(), vpGovObjsTmp.end(), insecureRand);

    for (int i = 0; i < nMaxObjRequestsPerNode; ++i) {
        uint256 nHashGovobj;

        // ask for triggers first
        if(vpGovObjsTriggersTmp.size()) {
            nHashGovobj = vpGovObjsTriggersTmp.back()->GetHash();
        } else {
            if(vpGovObjsTmp.empty()) break;
            nHashGovobj = vpGovObjsTmp.back()->GetHash();
        }
        bool fAsked = false;
        BOOST_FOREACH(CNode* pnode, vNodesCopy) {
            // only use reqular peers, don't try to ask from temporary nodes we connected to -
            // they stay connected for a short period of time and it's possible that we won't get everything we should
            if(pnode->fMasternode) continue;
            // only use up to date peers
            if(pnode->nVersion < MIN_GOVERNANCE_PEER_PROTO_VERSION) continue;
            // stop early to prevent setAskFor overflow
            size_t nProjectedSize = pnode->setAskFor.size() + nProjectedVotes;
            if(nProjectedSize > SETASKFOR_MAX_SZ/2) continue;
            // to early to ask the same node
            if(mapAskedRecently[nHashGovobj].count(pnode->addr)) continue;

            RequestGovernanceObject(pnode, nHashGovobj, true);
            mapAskedRecently[nHashGovobj][pnode->addr] = nNow + nTimeout;
            fAsked = true;
            // stop loop if max number of peers per obj was asked
            if(mapAskedRecently[nHashGovobj].size() >= nPeersPerHashMax) break;
        }
        // NOTE: this should match `if` above (the one before `while`)
        if(vpGovObjsTriggersTmp.size()) {
            vpGovObjsTriggersTmp.pop_back();
        } else {
            vpGovObjsTmp.pop_back();
        }
        if(!fAsked) i--;
    }
    LogPrint("governance", "CGovernanceManager::RequestGovernanceObjectVotes -- end: vpGovObjsTriggersTmp %d vpGovObjsTmp %d mapAskedRecently %d\n",
                vpGovObjsTriggersTmp.size(), vpGovObjsTmp.size(), mapAskedRecently.size());
}

bool CGovernanceManager::AcceptObjectMessage(const uint256& nHash)
{
    LOCK(cs);
    return AcceptMessage(nHash, setRequestedObjects);
}

bool CGovernanceManager::AcceptVoteMessage(const uint256& nHash)
{
    LOCK(cs);
    return AcceptMessage(nHash, setRequestedVotes);
}

bool CGovernanceManager::AcceptMessage(const uint256& nHash, hash_s_t& setHash)
{
    hash_s_it it = setHash.find(nHash);
    if(it == setHash.end()) {
        // We never requested this
        return false;
    }
    // Only accept one response
    setHash.erase(it);
    return true;
}

void CGovernanceManager::RebuildIndexes()
{
    mapVoteToObject.Clear();
    for(object_m_it it = mapObjects.begin(); it != mapObjects.end(); ++it) {
        CGovernanceObject& govobj = it->second;
        std::vector<CGovernanceVote> vecVotes = govobj.GetVoteFile().GetVotes();
        for(size_t i = 0; i < vecVotes.size(); ++i) {
            mapVoteToObject.Insert(vecVotes[i].GetHash(), &govobj);
        }
    }
}

int CGovernanceManager::GetMasternodeIndex(const CTxIn& masternodeVin)
{
    LOCK(cs);
    bool fIndexRebuilt = false;
    int nMNIndex = mnodeman.GetMasternodeIndex(masternodeVin, fIndexRebuilt);
    if(fIndexRebuilt) {
        RebuildVoteMaps();
        nMNIndex = mnodeman.GetMasternodeIndex(masternodeVin, fIndexRebuilt);
        if(fIndexRebuilt) {
            LogPrintf("CGovernanceManager::GetMasternodeIndex -- WARNING: vote map rebuild failed\n");
        }
    }
    return nMNIndex;
}

void CGovernanceManager::RebuildVoteMaps()
{
    for(object_m_it it = mapObjects.begin(); it != mapObjects.end(); ++it) {
        it->second.RebuildVoteMap();
    }
    mnodeman.ClearOldMasternodeIndex();
}

void CGovernanceManager::AddCachedTriggers()
{
    LOCK(cs);

    for(object_m_it it = mapObjects.begin(); it != mapObjects.end(); ++it) {
        CGovernanceObject& govobj = it->second;
        
        if(govobj.nObjectType != GOVERNANCE_OBJECT_TRIGGER) {
            continue;
        }

        triggerman.AddNewTrigger(govobj.GetHash());
    }
}

void CGovernanceManager::InitOnLoad()
{
    LOCK(cs);
    int64_t nStart = GetTimeMillis();
    LogPrintf("Preparing masternode indexes and governance triggers...\n");
    RebuildIndexes();
    AddCachedTriggers();
    LogPrintf("Masternode indexes and governance triggers prepared  %dms\n", GetTimeMillis() - nStart);
    LogPrintf("     %s\n", ToString());
}

std::string CGovernanceManager::ToString() const
{
    LOCK(cs);

    int nProposalCount = 0;
    int nTriggerCount = 0;
    int nWatchdogCount = 0;
    int nOtherCount = 0;

    object_m_cit it = mapObjects.begin();

    while(it != mapObjects.end()) {
        switch(it->second.GetObjectType()) {
            case GOVERNANCE_OBJECT_PROPOSAL:
                nProposalCount++;
                break;
            case GOVERNANCE_OBJECT_TRIGGER:
                nTriggerCount++;
                break;
            case GOVERNANCE_OBJECT_WATCHDOG:
                nWatchdogCount++;
                break;
            default:
                nOtherCount++;
                break;
        }
        ++it;
    }

    return strprintf("Governance Objects: %d (Proposals: %d, Triggers: %d, Watchdogs: %d, Other: %d; Seen: %d), Votes: %d",
                    (int)mapObjects.size(),
                    nProposalCount, nTriggerCount, nWatchdogCount, nOtherCount, (int)mapSeenGovernanceObjects.size(),
                    (int)mapVoteToObject.GetSize());
}

void CGovernanceManager::UpdatedBlockTip(const CBlockIndex *pindex)
{
    // Note this gets called from ActivateBestChain without cs_main being held
    // so it should be safe to lock our mutex here without risking a deadlock
    // On the other hand it should be safe for us to access pindex without holding a lock
    // on cs_main because the CBlockIndex objects are dynamically allocated and
    // presumably never deleted.
    if(!pindex) {
        return;
    }

    LOCK(cs);
    pCurrentBlockIndex = pindex;
    nCachedBlockHeight = pCurrentBlockIndex->nHeight;
    LogPrint("gobject", "CGovernanceManager::UpdatedBlockTip pCurrentBlockIndex->nHeight: %d\n", pCurrentBlockIndex->nHeight);

    // TO REPROCESS OBJECTS WE SHOULD BE SYNCED

    if(!fLiteMode && masternodeSync.IsSynced())
        NewBlock();
}
