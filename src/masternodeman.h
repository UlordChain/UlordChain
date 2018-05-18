// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MASTERNODEMAN_H
#define MASTERNODEMAN_H

#include "masternode.h"
#include "sync.h"

#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>


using namespace std;

class CMasternodeMan;

extern CMasternodeMan mnodeman;
extern CService ucenterservice;


/**
 * Provides a forward and reverse index between MN vin's and integers.
 *
 * This mapping is normally add-only and is expected to be permanent
 * It is only rebuilt if the size of the index exceeds the expected maximum number
 * of MN's and the current number of known MN's.
 *
 * The external interface to this index is provided via delegation by CMasternodeMan
 */
class CMasternodeIndex
{
public: // Types
    typedef std::map<CTxIn,int> index_m_t;

    typedef index_m_t::iterator index_m_it;

    typedef index_m_t::const_iterator index_m_cit;

    typedef std::map<int,CTxIn> rindex_m_t;

    typedef rindex_m_t::iterator rindex_m_it;

    typedef rindex_m_t::const_iterator rindex_m_cit;

private:
    int                  nSize;

    index_m_t            mapIndex;

    rindex_m_t           mapReverseIndex;

public:
    CMasternodeIndex();

    int GetSize() const {
        return nSize;
    }

    /// Retrieve masternode vin by index
    bool Get(int nIndex, CTxIn& vinMasternode) const;

    /// Get index of a masternode vin
    int GetMasternodeIndex(const CTxIn& vinMasternode) const;

    void AddMasternodeVIN(const CTxIn& vinMasternode);

    void Clear();

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(mapIndex);
        if(ser_action.ForRead()) {
            RebuildIndex();
        }
    }

private:
    void RebuildIndex();

};

class CMasternodeMan
{
public:
    typedef std::map<CTxIn,int> index_m_t;

    typedef index_m_t::iterator index_m_it;

    typedef index_m_t::const_iterator index_m_cit;

private:
    static const int MAX_EXPECTED_INDEX_SIZE = 30000;

    /// Only allow 1 index rebuild per hour
    static const int64_t MIN_INDEX_REBUILD_TIME = 3600;

    static const std::string SERIALIZATION_VERSION_STRING;

    static const int DSEG_UPDATE_SECONDS        = 3 * 60 * 60;

    static const int LAST_PAID_SCAN_BLOCKS      = 100;

    static const int MIN_POSE_PROTO_VERSION     = 70203;
    static const int MAX_POSE_RANK              = 10;
    static const int MAX_POSE_BLOCKS            = 10;

    static const int MNB_RECOVERY_QUORUM_TOTAL      = 10;
    static const int MNB_RECOVERY_QUORUM_REQUIRED   = 6;
    static const int MNB_RECOVERY_MAX_ASK_ENTRIES   = 10;
    static const int MNB_RECOVERY_WAIT_SECONDS      = 60;
    static const int MNB_RECOVERY_RETRY_SECONDS     = 3 * 60 * 60;


    // critical section to protect the inner data structures
    mutable CCriticalSection cs;

    // Keep track of current block index
    const CBlockIndex *pCurrentBlockIndex;

    // map to hold all MNs
    std::vector<CMasternode> vMasternodes;
    // who's asked for the Masternode list and the last time
    std::map<CNetAddr, int64_t> mAskedUsForMasternodeList;
    // who we asked for the Masternode list and the last time
    std::map<CNetAddr, int64_t> mWeAskedForMasternodeList;
    // which Masternodes we've asked for
    std::map<COutPoint, std::map<CNetAddr, int64_t> > mWeAskedForMasternodeListEntry;
    // who we asked for the masternode verification
    std::map<CNetAddr, CMasternodeVerification> mWeAskedForVerification;

    // these maps are used for masternode recovery from MASTERNODE_NEW_START_REQUIRED state
    std::map<uint256, std::pair< int64_t, std::set<CNetAddr> > > mMnbRecoveryRequests;
    std::map<uint256, std::vector<CMasternodeBroadcast> > mMnbRecoveryGoodReplies;
    std::list< std::pair<CService, uint256> > listScheduledMnbRequestConnections;

    int64_t nLastIndexRebuildTime;

    CMasternodeIndex indexMasternodes;

    CMasternodeIndex indexMasternodesOld;

    /// Set when index has been rebuilt, clear when read
    bool fIndexRebuilt;

    /// Set when masternodes are added, cleared when CGovernanceManager is notified
    bool fMasternodesAdded;

    /// Set when masternodes are removed, cleared when CGovernanceManager is notified
    bool fMasternodesRemoved;

    std::vector<uint256> vecDirtyGovernanceObjectHashes;

    int64_t nLastWatchdogVoteTime;

    friend class CMasternodeSync;

public:
    // Keep track of all broadcasts I've seen
    std::map<uint256, std::pair<int64_t, CMasternodeBroadcast> > mapSeenMasternodeBroadcast;
    // Keep track of all pings I've seen
    std::map<uint256, CMasternodePing> mapSeenMasternodePing;
    // Keep track of all verifications I've seen
    std::map<uint256, CMasternodeVerification> mapSeenMasternodeVerification;
    // keep track of dsq count to prevent masternodes from gaming darksend queue
    int64_t nDsqCount;


    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        LOCK(cs);
        std::string strVersion;
        if(ser_action.ForRead()) {
            READWRITE(strVersion);
        }
        else {
            strVersion = SERIALIZATION_VERSION_STRING; 
            READWRITE(strVersion);
        }

        READWRITE(vMasternodes);
        READWRITE(mAskedUsForMasternodeList);
        READWRITE(mWeAskedForMasternodeList);
        READWRITE(mWeAskedForMasternodeListEntry);
        READWRITE(mMnbRecoveryRequests);
        READWRITE(mMnbRecoveryGoodReplies);
        READWRITE(nLastWatchdogVoteTime);
        READWRITE(nDsqCount);

        READWRITE(mapSeenMasternodeBroadcast);
        READWRITE(mapSeenMasternodePing);
        READWRITE(indexMasternodes);
        if(ser_action.ForRead() && (strVersion != SERIALIZATION_VERSION_STRING)) {
            Clear();
        }
    }

    CMasternodeMan();

    /// Add an entry
    bool Add(CMasternode &mn);
    
    /// Check and activate the master node.
    bool CheckActiveMaster(CMasternode &mn);

    /// Ask (source) node for mnb
    void AskForMN(CNode *pnode, const CTxIn &vin);
    void AskForMnb(CNode *pnode, const uint256 &hash);

	///for test
	void SetRegisteredCheckInterval(int time);

    /// Check all Masternodes
    void Check();

    /// Check all Masternodes and remove inactive
    void CheckAndRemove();

    /// Clear Masternode vector
    void Clear();

    /// Count Masternodes filtered by nProtocolVersion.
    /// Masternode nProtocolVersion should match or be above the one specified in param here.
    int CountMasternodes(int nProtocolVersion = -1);
    /// Count enabled Masternodes filtered by nProtocolVersion.
    /// Masternode nProtocolVersion should match or be above the one specified in param here.
    int CountEnabled(int nProtocolVersion = -1);

    /// Count Masternodes by network type - NET_IPV4, NET_IPV6, NET_TOR
    // int CountByIP(int nNetworkType);

    void DsegUpdate(CNode* pnode);

    /// Find an entry
    CMasternode* Find(const CScript &payee);
    CMasternode* Find(const CTxIn& vin);
    CMasternode* Find(const CPubKey& pubKeyMasternode);

    /// Versions of Find that are safe to use from outside the class
    bool Get(const CPubKey& pubKeyMasternode, CMasternode& masternode);
    bool Get(const CTxIn& vin, CMasternode& masternode);

    /// Retrieve masternode vin by index
    bool Get(int nIndex, CTxIn& vinMasternode, bool& fIndexRebuiltOut) {
        LOCK(cs);
        fIndexRebuiltOut = fIndexRebuilt;
        return indexMasternodes.Get(nIndex, vinMasternode);
    }

    bool GetIndexRebuiltFlag() {
        LOCK(cs);
        return fIndexRebuilt;
    }

    /// Get index of a masternode vin
    int GetMasternodeIndex(const CTxIn& vinMasternode) {
        LOCK(cs);
        return indexMasternodes.GetMasternodeIndex(vinMasternode);
    }

    /// Get old index of a masternode vin
    int GetMasternodeIndexOld(const CTxIn& vinMasternode) {
        LOCK(cs);
        return indexMasternodesOld.GetMasternodeIndex(vinMasternode);
    }

    /// Get masternode VIN for an old index value
    bool GetMasternodeVinForIndexOld(int nMasternodeIndex, CTxIn& vinMasternodeOut) {
        LOCK(cs);
        return indexMasternodesOld.Get(nMasternodeIndex, vinMasternodeOut);
    }

    /// Get index of a masternode vin, returning rebuild flag
    int GetMasternodeIndex(const CTxIn& vinMasternode, bool& fIndexRebuiltOut) {
        LOCK(cs);
        fIndexRebuiltOut = fIndexRebuilt;
        return indexMasternodes.GetMasternodeIndex(vinMasternode);
    }

    void ClearOldMasternodeIndex() {
        LOCK(cs);
        indexMasternodesOld.Clear();
        fIndexRebuilt = false;
    }

    bool Has(const CTxIn& vin);

    masternode_info_t GetMasternodeInfo(const CTxIn& vin);

    masternode_info_t GetMasternodeInfo(const CPubKey& pubKeyMasternode);

    /// Find an entry in the masternode list that is next to be paid
    CMasternode* GetNextMasternodeInQueueForPayment(int nBlockHeight, bool fFilterSigTime, int& nCount);
    /// Same as above but use current block height
    CMasternode* GetNextMasternodeInQueueForPayment(bool fFilterSigTime, int& nCount);

    /// Find a random entry
    CMasternode* FindRandomNotInVec(const std::vector<CTxIn> &vecToExclude, int nProtocolVersion = -1);

    std::vector<CMasternode> GetFullMasternodeVector() { return vMasternodes; }

    std::vector<std::pair<int, CMasternode> > GetMasternodeRanks(int nBlockHeight = -1, int nMinProtocol=0);
    int GetMasternodeRank(const CTxIn &vin, int nBlockHeight, int nMinProtocol=0, bool fOnlyActive=true);
    CMasternode* GetMasternodeByRank(int nRank, int nBlockHeight, int nMinProtocol=0, bool fOnlyActive=true);

    void ProcessMasternodeConnections();
    std::pair<CService, std::set<uint256> > PopScheduledMnbRequestConnection();

    void ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);

    void DoFullVerificationStep();
    void CheckSameAddr();
    bool SendVerifyRequest(const CAddress& addr, const std::vector<CMasternode*>& vSortedByAddr);
    void SendVerifyReply(CNode* pnode, CMasternodeVerification& mnv);
    void ProcessVerifyReply(CNode* pnode, CMasternodeVerification& mnv);
    void ProcessVerifyBroadcast(CNode* pnode, const CMasternodeVerification& mnv);

    /// Return the number of (unique) Masternodes
    int size() { return vMasternodes.size(); }

    std::string ToString() const;

    /// Update masternode list and maps using provided CMasternodeBroadcast
    void UpdateMasternodeList(CMasternodeBroadcast mnb);
    /// Perform complete check and only then update list and maps
    bool CheckMnbAndUpdateMasternodeList(CNode* pfrom, CMasternodeBroadcast mnb, int& nDos);
    bool IsMnbRecoveryRequested(const uint256& hash) { return mMnbRecoveryRequests.count(hash); }

    void UpdateLastPaid();

    void CheckAndRebuildMasternodeIndex();

    void AddDirtyGovernanceObjectHash(const uint256& nHash)
    {
        LOCK(cs);
        vecDirtyGovernanceObjectHashes.push_back(nHash);
    }

    std::vector<uint256> GetAndClearDirtyGovernanceObjectHashes()
    {
        LOCK(cs);
        std::vector<uint256> vecTmp = vecDirtyGovernanceObjectHashes;
        vecDirtyGovernanceObjectHashes.clear();
        return vecTmp;;
    }

    bool IsWatchdogActive();
    void UpdateWatchdogVoteTime(const CTxIn& vin);
    void AddGovernanceVote(const CTxIn& vin, uint256 nGovernanceObjectHash);
    void RemoveGovernanceObject(uint256 nGovernanceObjectHash);

    void CheckMasternode(const CTxIn& vin, bool fForce = false);
    void CheckMasternode(const CPubKey& pubKeyMasternode, bool fForce = false);

    int GetMasternodeState(const CTxIn& vin);
    int GetMasternodeState(const CPubKey& pubKeyMasternode);

    bool IsMasternodePingedWithin(const CTxIn& vin, int nSeconds, int64_t nTimeToCheckAt = -1);
    void SetMasternodeLastPing(const CTxIn& vin, const CMasternodePing& mnp);

    void UpdatedBlockTip(const CBlockIndex *pindex);

    /**
     * Called to notify CGovernanceManager that the masternode index has been updated.
     * Must be called while not holding the CMasternodeMan::cs mutex
     */
    void NotifyMasternodeUpdates();

};

//================================================================masternode center server ===============================================
// master node  quest  master register center  about master node info
#define Center_Server_Version 7001
#define Center_Server_VerFlag "ver"
#define Center_Server_IP "118.190.150.58"
#define Center_Server_Port "3009"
#define MasterNodeCoin 10000 
#define WaitTimeOut (60*5)
#define MAX_LENGTH 65536
#define Length_Of_Char 5

/*extern bool CheckMasterInfoOfTx(CTxIn &vin);
extern bool InitAndConnectOfSock(std::string&str);
extern void SendToCenter(int SockFd,std::string&str);
extern bool ReceiveFromCenter(int SockFd);
static bool b_Used= false;*/

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
       _verfyflag=std::string("#$%@");  
       
    }  
    mstnodequest(){}
    int        _msgversion; 	
    int        _questtype;
	int64_t    _timeStamps;
    std::string     _verfyflag;
    std::string     _masteraddr;
    friend class boost::serialization::access;
    
    template<class Archive>
    void serialize(Archive& ar, const unsigned int version)
    {  
        ar & _verfyflag;
        ar & _msgversion;
		ar & _timeStamps;
        ar & _questtype;
        ar & _masteraddr;
        //ar & _llAmount;  
    }  
    int GetVersion() const {return _msgversion;}  
    int GetQuestType() const {return _questtype;}  
    void  SetMasterAddr(std::string addr){ _masteraddr=addr;}
};

//extern mstnodequest RequestMsgType(Center_Server_Version,MST_QUEST::MST_QUEST_ONE);

// master node quest version 
class  mstnoderes
{
public:
    mstnoderes(int version  ):_msgversion(version)
    {
       _verfyflag=std::string("#$%@");
       _num=1;
    }

    mstnoderes(){}

    int             _msgversion;
    int             _num;
    std::string     _verfyflag;
    std::string     _signstr;
    friend class boost::serialization::access;

    template<class Archive>
    void serialize(Archive& ar, const unsigned int version)
    {
        ar & _verfyflag;
        ar & _msgversion;
        ar & _num;
        ar & _signstr;  // 使用 查询的第一个地址来签名  。 
        //ar & _llAmount;  
    }
    int GetVersion() const {return _msgversion;}
    int GetNum() const {return _num;}
};
//extern mstnoderes RetMsgType;

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
        ar & _validflag;
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
    int GetValidFlag() const {return _validflag;}  
    std::string GetMasterAddr() const {return _masteraddr;}  

    CMstNodeData & operator=(CMstNodeData &b)
    {
        _version   = b._version;
        _masteraddr= b._masteraddr;
        _hostname  = b._hostname;
        _hostip    = b._hostip;
        _validflag = b._validflag;
        return * this;
    }
public:  
    int _version;  
    std::string _masteraddr; // node addr
    std::string _txid;      //  
    std::string _hostname;  // 
    std::string _hostip;    // 
    int         _validflag; //
    int         _time;
    long long   _llAmount;  // 
    std::string _text;  
};  

#endif
