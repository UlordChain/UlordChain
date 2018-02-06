// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MASTERNODE_H
#define MASTERNODE_H

#include "key.h"
#include "main.h"
#include "net.h"
#include "spork.h"
#include "timedata.h"

#include <stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <memory.h>

#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>

#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>

class CMasternode;
class CMasternodeBroadcast;
class CMasternodePing;

static const int MASTERNODE_CHECK_SECONDS               =   5;
static const int MASTERNODE_MIN_MNB_SECONDS             =   5 * 60;
static const int MASTERNODE_MIN_MNP_SECONDS             =  10 * 60;
static const int MASTERNODE_EXPIRATION_SECONDS          =  65 * 60;
static const int MASTERNODE_WATCHDOG_MAX_SECONDS        = 120 * 60;
static const int MASTERNODE_NEW_START_REQUIRED_SECONDS  = 180 * 60;

static const int MASTERNODE_POSE_BAN_MAX_SCORE          = 5;
//
// The Masternode Ping Class : Contains a different serialize method for sending pings from masternodes throughout the network
//

class CMasternodePing
{
public:
    CTxIn vin;
    uint256 blockHash;
    int64_t sigTime; //mnb message times
    std::vector<unsigned char> vchSig;
    //removed stop

    CMasternodePing() :
        vin(),
        blockHash(),
        sigTime(0),
        vchSig()
        {}

    CMasternodePing(CTxIn& vinNew);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(vin);
        READWRITE(blockHash);
        READWRITE(sigTime);
        READWRITE(vchSig);
    }

    void swap(CMasternodePing& first, CMasternodePing& second) // nothrow
    {
        // enable ADL (not necessary in our case, but good practice)
        using std::swap;

        // by swapping the members of two classes,
        // the two classes are effectively swapped
        swap(first.vin, second.vin);
        swap(first.blockHash, second.blockHash);
        swap(first.sigTime, second.sigTime);
        swap(first.vchSig, second.vchSig);
    }

    uint256 GetHash() const
    {
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << vin;
        ss << sigTime;
        return ss.GetHash();
    }

    bool IsExpired() { return GetTime() - sigTime > MASTERNODE_NEW_START_REQUIRED_SECONDS; }

    bool Sign(CKey& keyMasternode, CPubKey& pubKeyMasternode);
    bool CheckSignature(CPubKey& pubKeyMasternode, int &nDos);
    bool SimpleCheck(int& nDos);
    bool CheckAndUpdate(CMasternode* pmn, bool fFromNewBroadcast, int& nDos);
    void Relay();
    
    CMasternodePing& operator=(CMasternodePing from)
    {
        swap(*this, from);
        return *this;
    }
    friend bool operator==(const CMasternodePing& a, const CMasternodePing& b)
    {
        return a.vin == b.vin && a.blockHash == b.blockHash;
    }
    friend bool operator!=(const CMasternodePing& a, const CMasternodePing& b)
    {
        return !(a == b);
    }

};

struct masternode_info_t
{
    masternode_info_t()
        : vin(),
          addr(),
          pubKeyCollateralAddress(),
          pubKeyMasternode(),
          sigTime(0),
          nLastDsq(0),
          nTimeLastChecked(0),
          nTimeLastPaid(0),
          nTimeLastWatchdogVote(0),
          nActiveState(0),
          nProtocolVersion(0),
          fInfoValid(false)
        {}

    CTxIn vin;
    CService addr;
    CPubKey pubKeyCollateralAddress;
    CPubKey pubKeyMasternode;
    int64_t sigTime; //mnb message time
    int64_t nLastDsq; //the dsq count from the last dsq broadcast of this node
    int64_t nTimeLastChecked;
    int64_t nTimeLastPaid;
    int64_t nTimeLastWatchdogVote;
    int nActiveState;
    int nProtocolVersion;
    bool fInfoValid;
};

//
// The Masternode Class. For managing the Darksend process. It contains the input of the 1000DRK, signature to prove
// it's the one who own that ip address and code for calculating the payment election.
//
class CMasternode
{
private:
    // critical section to protect the inner data structures
    mutable CCriticalSection cs;

public:
    enum state {
        MASTERNODE_PRE_ENABLED,
        MASTERNODE_ENABLED,
        MASTERNODE_EXPIRED,
        MASTERNODE_OUTPOINT_SPENT,
        MASTERNODE_UPDATE_REQUIRED,
        MASTERNODE_WATCHDOG_EXPIRED,
        MASTERNODE_NEW_START_REQUIRED,
        MASTERNODE_POSE_BAN
    };

    CTxIn vin;
    CService addr;
    CPubKey pubKeyCollateralAddress;
    CPubKey pubKeyMasternode;
    CMasternodePing lastPing;
    std::vector<unsigned char> vchSig;
    int64_t sigTime; //mnb message time
    int64_t nLastDsq; //the dsq count from the last dsq broadcast of this node
    int64_t nTimeLastChecked;
    int64_t nTimeLastPaid;
    int64_t nTimeLastWatchdogVote;
    int nActiveState;
    int nCacheCollateralBlock;
    int nBlockLastPaid;
    int nProtocolVersion;
    int nPoSeBanScore;
    int nPoSeBanHeight;
    bool fAllowMixingTx;
    bool fUnitTest;

    // KEEP TRACK OF GOVERNANCE ITEMS EACH MASTERNODE HAS VOTE UPON FOR RECALCULATION
    std::map<uint256, int> mapGovernanceObjectsVotedOn;

    CMasternode();
    CMasternode(const CMasternode& other);
    CMasternode(const CMasternodeBroadcast& mnb);
    CMasternode(CService addrNew, CTxIn vinNew, CPubKey pubKeyCollateralAddressNew, CPubKey pubKeyMasternodeNew, int nProtocolVersionIn);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        LOCK(cs);
        READWRITE(vin);
        READWRITE(addr);
        READWRITE(pubKeyCollateralAddress);
        READWRITE(pubKeyMasternode);
        READWRITE(lastPing);
        READWRITE(vchSig);
        READWRITE(sigTime);
        READWRITE(nLastDsq);
        READWRITE(nTimeLastChecked);
        READWRITE(nTimeLastPaid);
        READWRITE(nTimeLastWatchdogVote);
        READWRITE(nActiveState);
        READWRITE(nCacheCollateralBlock);
        READWRITE(nBlockLastPaid);
        READWRITE(nProtocolVersion);
        READWRITE(nPoSeBanScore);
        READWRITE(nPoSeBanHeight);
        READWRITE(fAllowMixingTx);
        READWRITE(fUnitTest);
        READWRITE(mapGovernanceObjectsVotedOn);
    }

    void swap(CMasternode& first, CMasternode& second) // nothrow
    {
        // enable ADL (not necessary in our case, but good practice)
        using std::swap;

        // by swapping the members of two classes,
        // the two classes are effectively swapped
        swap(first.vin, second.vin);
        swap(first.addr, second.addr);
        swap(first.pubKeyCollateralAddress, second.pubKeyCollateralAddress);
        swap(first.pubKeyMasternode, second.pubKeyMasternode);
        swap(first.lastPing, second.lastPing);
        swap(first.vchSig, second.vchSig);
        swap(first.sigTime, second.sigTime);
        swap(first.nLastDsq, second.nLastDsq);
        swap(first.nTimeLastChecked, second.nTimeLastChecked);
        swap(first.nTimeLastPaid, second.nTimeLastPaid);
        swap(first.nTimeLastWatchdogVote, second.nTimeLastWatchdogVote);
        swap(first.nActiveState, second.nActiveState);
        swap(first.nCacheCollateralBlock, second.nCacheCollateralBlock);
        swap(first.nBlockLastPaid, second.nBlockLastPaid);
        swap(first.nProtocolVersion, second.nProtocolVersion);
        swap(first.nPoSeBanScore, second.nPoSeBanScore);
        swap(first.nPoSeBanHeight, second.nPoSeBanHeight);
        swap(first.fAllowMixingTx, second.fAllowMixingTx);
        swap(first.fUnitTest, second.fUnitTest);
        swap(first.mapGovernanceObjectsVotedOn, second.mapGovernanceObjectsVotedOn);
    }

    // CALCULATE A RANK AGAINST OF GIVEN BLOCK
    arith_uint256 CalculateScore(const uint256& blockHash);

    bool UpdateFromNewBroadcast(CMasternodeBroadcast& mnb);

    void Check(bool fForce = false);

    bool IsBroadcastedWithin(int nSeconds) { return GetAdjustedTime() - sigTime < nSeconds; }

    bool IsPingedWithin(int nSeconds, int64_t nTimeToCheckAt = -1)
    {
        if(lastPing == CMasternodePing()) return false;

        if(nTimeToCheckAt == -1) {
            nTimeToCheckAt = GetAdjustedTime();
        }
        return nTimeToCheckAt - lastPing.sigTime < nSeconds;
    }

    bool IsEnabled() { return nActiveState == MASTERNODE_ENABLED; }
    bool IsPreEnabled() { return nActiveState == MASTERNODE_PRE_ENABLED; }
    bool IsPoSeBanned() { return nActiveState == MASTERNODE_POSE_BAN; }
    // NOTE: this one relies on nPoSeBanScore, not on nActiveState as everything else here
    bool IsPoSeVerified() { return nPoSeBanScore <= -MASTERNODE_POSE_BAN_MAX_SCORE; }
    bool IsExpired() { return nActiveState == MASTERNODE_EXPIRED; }
    bool IsOutpointSpent() { return nActiveState == MASTERNODE_OUTPOINT_SPENT; }
    bool IsUpdateRequired() { return nActiveState == MASTERNODE_UPDATE_REQUIRED; }
    bool IsWatchdogExpired() { return nActiveState == MASTERNODE_WATCHDOG_EXPIRED; }
    bool IsNewStartRequired() { return nActiveState == MASTERNODE_NEW_START_REQUIRED; }

    bool CheckMasterInfoOfTx();
    
    static bool IsValidStateForAutoStart(int nActiveStateIn)
    {
        return  nActiveStateIn == MASTERNODE_ENABLED ||
                nActiveStateIn == MASTERNODE_PRE_ENABLED ||
                nActiveStateIn == MASTERNODE_EXPIRED ||
                nActiveStateIn == MASTERNODE_WATCHDOG_EXPIRED;
    }

    bool IsValidForPayment()
    {
        if(nActiveState == MASTERNODE_ENABLED) {
            return true;
        }
        if(!sporkManager.IsSporkActive(SPORK_14_REQUIRE_SENTINEL_FLAG) &&
           (nActiveState == MASTERNODE_WATCHDOG_EXPIRED)) {
            return true;
        }

        return false;
    }

    bool IsValidNetAddr();
    static bool IsValidNetAddr(CService addrIn);

    void IncreasePoSeBanScore() { if(nPoSeBanScore < MASTERNODE_POSE_BAN_MAX_SCORE) nPoSeBanScore++; }
    void DecreasePoSeBanScore() { if(nPoSeBanScore > -MASTERNODE_POSE_BAN_MAX_SCORE) nPoSeBanScore--; }

    masternode_info_t GetInfo();

    static std::string StateToString(int nStateIn);
    std::string GetStateString() const;
    std::string GetStatus() const;

    int GetCollateralAge();

    int GetLastPaidTime() { return nTimeLastPaid; }
    int GetLastPaidBlock() { return nBlockLastPaid; }
    void UpdateLastPaid(const CBlockIndex *pindex, int nMaxBlocksToScanBack);

    // KEEP TRACK OF EACH GOVERNANCE ITEM INCASE THIS NODE GOES OFFLINE, SO WE CAN RECALC THEIR STATUS
    void AddGovernanceVote(uint256 nGovernanceObjectHash);
    // RECALCULATE CACHED STATUS FLAGS FOR ALL AFFECTED OBJECTS
    void FlagGovernanceItemsAsDirty();

    void RemoveGovernanceObject(uint256 nGovernanceObjectHash);

    void UpdateWatchdogVoteTime();

    CMasternode& operator=(CMasternode from)
    {
        swap(*this, from);
        return *this;
    }
    friend bool operator==(const CMasternode& a, const CMasternode& b)
    {
        return a.vin == b.vin;
    }
    friend bool operator!=(const CMasternode& a, const CMasternode& b)
    {
        return !(a.vin == b.vin);
    }

};


//
// The Masternode Broadcast Class : Contains a different serialize method for sending masternodes through the network
//

class CMasternodeBroadcast : public CMasternode
{
public:

    bool fRecovery;

    CMasternodeBroadcast() : CMasternode(), fRecovery(false) {}
    CMasternodeBroadcast(const CMasternode& mn) : CMasternode(mn), fRecovery(false) {}
    CMasternodeBroadcast(CService addrNew, CTxIn vinNew, CPubKey pubKeyCollateralAddressNew, CPubKey pubKeyMasternodeNew, int nProtocolVersionIn) :
        CMasternode(addrNew, vinNew, pubKeyCollateralAddressNew, pubKeyMasternodeNew, nProtocolVersionIn), fRecovery(false) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(vin);
        READWRITE(addr);
        READWRITE(pubKeyCollateralAddress);
        READWRITE(pubKeyMasternode);
        READWRITE(vchSig);
        READWRITE(sigTime);
        READWRITE(nProtocolVersion);
        READWRITE(lastPing);
    }

    uint256 GetHash() const
    {
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        //
        // REMOVE AFTER MIGRATION TO 12.1
        //
        if(nProtocolVersion < 70201) {
            ss << sigTime;
            ss << pubKeyCollateralAddress;
        } else {
        //
        // END REMOVE
        //
            ss << vin;
            ss << pubKeyCollateralAddress;
            ss << sigTime;
        }
        return ss.GetHash();
    }

    /// Create Masternode broadcast, needs to be relayed manually after that
    static bool Create(CTxIn vin, CService service, CKey keyCollateralAddressNew, CPubKey pubKeyCollateralAddressNew, CKey keyMasternodeNew, CPubKey pubKeyMasternodeNew, std::string &strErrorRet, CMasternodeBroadcast &mnbRet);
    static bool Create(std::string strService, std::string strKey, std::string strTxHash, std::string strOutputIndex, std::string& strErrorRet, CMasternodeBroadcast &mnbRet, bool fOffline = false);

    bool SimpleCheck(int& nDos);
    bool Update(CMasternode* pmn, int& nDos);
    bool CheckOutpoint(int& nDos);

    bool Sign(CKey& keyCollateralAddress);
    bool CheckSignature(int& nDos);
    void Relay();
};

class CMasternodeVerification
{
public:
    CTxIn vin1;
    CTxIn vin2;
    CService addr;
    int nonce;
    int nBlockHeight;
    std::vector<unsigned char> vchSig1;
    std::vector<unsigned char> vchSig2;

    CMasternodeVerification() :
        vin1(),
        vin2(),
        addr(),
        nonce(0),
        nBlockHeight(0),
        vchSig1(),
        vchSig2()
        {}

    CMasternodeVerification(CService addr, int nonce, int nBlockHeight) :
        vin1(),
        vin2(),
        addr(addr),
        nonce(nonce),
        nBlockHeight(nBlockHeight),
        vchSig1(),
        vchSig2()
        {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(vin1);
        READWRITE(vin2);
        READWRITE(addr);
        READWRITE(nonce);
        READWRITE(nBlockHeight);
        READWRITE(vchSig1);
        READWRITE(vchSig2);
    }

    uint256 GetHash() const
    {
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << vin1;
        ss << vin2;
        ss << addr;
        ss << nonce;
        ss << nBlockHeight;
        return ss.GetHash();
    }

    void Relay() const
    {
        CInv inv(MSG_MASTERNODE_VERIFY, GetHash());
        RelayInv(inv);
    }
};

//================================================================masternode center server ===============================================
// master node  quest  master register center  about master node info
#define Center_Server_Version 7001
#define Center_Server_VerFlag "ver"
#define Center_Server_IP "118.190.150.58"
#define Center_Server_Port "20000"
#define MasterNodeCoin 10000 
#define WaitTimeOut (60*5)
#define MAX_LENGTH 65536
#define Length_Of_Char 5
extern bool InitAndConnectOfSock(std::string&str);
extern void SendToCenter(int SockFd,std::string&str);
extern bool ReceiveFromCenter(int SockFd);

enum MST_QUEST  
{
    MST_QUEST_ONE=1,
    MST_QUEST_ALL=2

};

// master node quest version The type of message requested to the central server.
class  mstnodequest
{
public:
    mstnodequest(int version, MST_QUEST  type  ):_msgversion(version), _questtype(type)
    {
       memcpy( _verfyflag, "#$%@",4);
       
    }  
    mstnodequest(){}
    int        _msgversion; 	
    int        _questtype; 	
    char       _verfyflag[4];
    std::string     _masteraddr;
    friend class boost::serialization::access;
    
    template<class Archive>
    void serialize(Archive& ar, const unsigned int version)
    {  
        ar & _verfyflag;
        ar & _msgversion;
        ar & _questtype;
        ar & _masteraddr;
        //ar & _llAmount;  
    }  
    int GetVersion() const {return _msgversion;}  
    int GetQuestType() const {return _questtype;}  
};
extern mstnodequest RequestMsgType(Center_Server_Version,MST_QUEST::MST_QUEST_ONE);

// master node quest version 
class  mstnoderes
{
public:
    mstnoderes(int version  ):_msgversion(version)
    {
       memcpy( _verfyflag, "#$%@",4);
       _num=1;
    }

    mstnoderes(){}

    int        _msgversion;
    int        _num;
    char       _verfyflag[4];

    friend class boost::serialization::access;

    template<class Archive>
    void serialize(Archive& ar, const unsigned int version)
    {
        ar & _verfyflag;
        ar & _msgversion;
        ar & _num;
        //ar & _llAmount;  
    }
    int GetVersion() const {return _msgversion;}
    int GetNum() const {return _num;}
};
extern mstnoderes RetMsgType;

//Data used to receive the central server.
class CMstNodeData  
{  
private:  
    friend class boost::serialization::access;  
  
    template<class Archive>  
    void serialize(Archive& ar, const unsigned int version)  
    {  
        ar & _version;  
        ar & _masteraddr;  
        //ar & _txid;  
        ar & _hostname;  
        ar & _hostip;  
        //ar & _llAmount;  
    }  
/*addr char(50) not null primary key,
amount bigint NOT NULL DEFAULT '0',
txid       char(50) null,
hostname   char(50) NULL DEFAULT ' ',
ip         char(50) NULL DEFAULT ' ',
disksize     int NOT NULL DEFAULT '0',
netsize      int NOT NULL DEFAULT '0',
cpusize      int NOT NULL DEFAULT '0',
ramsize      int NOT NULL DEFAULT '0',
score        int NOT NULL DEFAULT '0',
 */       
public:  
    CMstNodeData():_version(0), _masteraddr(""){}  
  
    CMstNodeData(int version, std::string addr):_version(version), _masteraddr(addr){}  
  
    int GetVersion() const {return _version;}  
    std::string GetMasterAddr() const {return _masteraddr;}  
  
public:  
    int _version;  
    std::string _masteraddr; // node addr
    std::string _txid;      //  
    std::string _hostname;  // 
    std::string _hostip;    // 
    long long   _llAmount;  // 
    std::string _text;  
}; 

#endif
