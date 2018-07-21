// Copyright (c) 2016-2018 Ulord Foundation Ltd.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ULORD_NAMETRIE_H
#define ULORD_NAMETRIE_H

#include "amount.h"
#include "serialize.h"
#include "uint256.h"
#include "util.h"
#include "dbwrapper.h"
#include "primitives/transaction.h"

#include <string>
#include <vector>
#include <map>

// leveldb keys
#define HASH_BLOCK 'h'
#define CURRENT_HEIGHT 't'
#define TRIE_NODE 'n'
#define CLAIM_QUEUE_ROW 'r'
#define CLAIM_QUEUE_NAME_ROW 'm'
#define EXP_QUEUE_ROW 'e'
#define SUPPORT 's'
#define SUPPORT_QUEUE_ROW 'u'
#define SUPPORT_QUEUE_NAME_ROW 'p'
#define SUPPORT_EXP_QUEUE_ROW 'x'

uint256 namegetValueHash(COutPoint outPoint, int nHeightOfLastTakeover);

class CNameValue
{
public:
    COutPoint outPoint;
    uint160 claimId;
    CAmount nAmount;
    CAmount nEffectiveAmount;
    int nHeight;
    int nValidAtHeight;
    std::string addr;
    std::string name;
    std::map<std::string,std::string>m_NameAddress;
    CNameValue() {};

    CNameValue(COutPoint outPoint, uint160 claimId, CAmount nAmount, int nHeight,
                int nValidAtHeight,std::string nName,std::string nAddr)
                : outPoint(outPoint), claimId(claimId)
                , nAmount(nAmount), nEffectiveAmount(nAmount)
                , nHeight(nHeight), nValidAtHeight(nValidAtHeight)
		, addr(nAddr),name(nName)
    {
	m_NameAddress[name]=addr;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(outPoint);
        READWRITE(claimId);
        READWRITE(nAmount);
        READWRITE(nHeight);
        READWRITE(nValidAtHeight);
    }
    
    bool operator<(const CNameValue& other) const
    {
        if (nEffectiveAmount < other.nEffectiveAmount)
            return true;
        else if (nEffectiveAmount == other.nEffectiveAmount)
        {
            if (nHeight > other.nHeight)
                return true;
            else if (nHeight == other.nHeight)
            {
                if (outPoint != other.outPoint && !(outPoint < other.outPoint))
                    return true;
            }
        }
        return false;
    }
    
    bool operator==(const CNameValue& other) const
    {
        return outPoint == other.outPoint && claimId == other.claimId && nAmount == other.nAmount && nHeight == other.nHeight && nValidAtHeight == other.nValidAtHeight;
    }
    
    bool operator!=(const CNameValue& other) const
    {
        return !(*this == other);
    }
};

class CSupportNameValue
{
public:
    COutPoint outPoint;
    uint160 supportedClaimId;
    CAmount nAmount;
    int nHeight;
    int nValidAtHeight;
    
    CSupportNameValue() {};
    CSupportNameValue(COutPoint outPoint, uint160 supportedClaimId,
                  CAmount nAmount, int nHeight, int nValidAtHeight)
                  : outPoint(outPoint), supportedClaimId(supportedClaimId)
                  , nAmount(nAmount), nHeight(nHeight)
                  , nValidAtHeight(nValidAtHeight)
    {}
    
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(outPoint);
        READWRITE(supportedClaimId);
        READWRITE(nAmount);
        READWRITE(nHeight);
        READWRITE(nValidAtHeight);
    }

    bool operator==(const CSupportNameValue& other) const
    {
        return outPoint == other.outPoint && supportedClaimId == other.supportedClaimId && nAmount == other.nAmount && nHeight == other.nHeight && nValidAtHeight == other.nValidAtHeight;
    }

    bool operator!=(const CSupportNameValue& other) const
    {
        return !(*this == other);
    }
};

class CNameTrieNode;
class CNameTrie;

typedef std::vector<CSupportNameValue> supportNameMapEntryType;

typedef std::map<unsigned char, CNameTrieNode*> nodeNameMapType;

typedef std::pair<std::string, CNameTrieNode> NamedNodeType;

class CNameTrieNode
{
public:
    CNameTrieNode() : nHeightOfLastTakeover(0) {}
    CNameTrieNode(uint256 hash) : hash(hash), nHeightOfLastTakeover(0) {}
    uint256 hash;
    nodeNameMapType children;
    int nHeightOfLastTakeover;
    std::vector<CNameValue> claims;

    bool insertClaim(CNameValue claim);
    bool removeClaim(const COutPoint& outPoint, CNameValue& claim);
    bool getBestClaim(CNameValue& claim) const;
    bool empty() const {return children.empty() && claims.empty();}
    bool haveClaim(const COutPoint& outPoint) const;
    void reorderClaims(supportNameMapEntryType& supports);
    
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(hash);
        READWRITE(claims);
        READWRITE(nHeightOfLastTakeover);
    }
    
    bool operator==(const CNameTrieNode& other) const
    {
        return hash == other.hash && claims == other.claims;
    }

    bool operator!=(const CNameTrieNode& other) const
    {
        return !(*this == other);
    }
};

struct nodeNamecompare
{
    bool operator() (const std::string& i, const std::string& j) const
    {
        if (i.size() == j.size())
            return i < j;
        return i.size() < j.size();
    }
};

struct NameoutPointHeightType
{
    COutPoint outPoint;
    int nHeight;

    NameoutPointHeightType() {}

    NameoutPointHeightType(COutPoint outPoint, int nHeight)
    : outPoint(outPoint), nHeight(nHeight) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(outPoint);
        READWRITE(nHeight);
    }

};

struct NameOutPointHeightType
{
    std::string name;
    COutPoint outPoint;
    int nHeight;

    NameOutPointHeightType() {}

    NameOutPointHeightType(std::string name, COutPoint outPoint, int nHeight)
    : name(name), outPoint(outPoint), nHeight(nHeight) {}
   
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(name);
        READWRITE(outPoint);
        READWRITE(nHeight);
    }
};

struct NameOutPointType
{
    std::string name;
    COutPoint outPoint;

    NameOutPointType() {}

    NameOutPointType(std::string name, COutPoint outPoint)
    : name(name), outPoint(outPoint) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(name);
        READWRITE(outPoint);
    }
};

typedef std::pair<std::string, CNameValue> NameQueueEntryType;

typedef std::pair<std::string, CSupportNameValue> NamesupportQueueEntryType;

typedef std::map<std::string, supportNameMapEntryType> NamesupportMapType;

typedef std::vector<NameoutPointHeightType> NamequeueNameRowType;
typedef std::map<std::string, NamequeueNameRowType> NamequeueNameType;

typedef std::vector<NameOutPointHeightType> insertNameUndoType;

typedef std::vector<NameOutPointType> expirationNameQueueRowType;
typedef std::map<int, expirationNameQueueRowType> expirationNameQueueType;

typedef std::vector<NameQueueEntryType> NameQueueRowType;
typedef std::map<int, NameQueueRowType> nameQueueType;

typedef std::vector<NamesupportQueueEntryType> NamesupportQueueRowType;
typedef std::map<int, NamesupportQueueRowType> supportNameQueueType;

typedef std::map<std::string, CNameTrieNode*, nodeNamecompare> NodenodeCacheType;

typedef std::map<std::string, uint256> hashMapType;

struct NameTrieForNameType
{
    std::vector<CNameValue> claims;
    std::vector<CSupportNameValue> supports;
    int nLastTakeoverHeight;

    NameTrieForNameType(std::vector<CNameValue> claims, std::vector<CSupportNameValue> supports, int nLastTakeoverHeight)
    : claims(claims), supports(supports), nLastTakeoverHeight(nLastTakeoverHeight) {}
};

class CNameTrieCache;

class CNameTrie
{
public:
    CNameTrie(bool fMemory = false, bool fWipe = false, int nProportionalDelayFactor = 32)
               : db(GetDataDir() / "nametrie", 100, fMemory, fWipe, false)
               , nCurrentHeight(1), nExpirationTime(262974)
               , nProportionalDelayFactor(nProportionalDelayFactor)
               , root(uint256S("0000000000000000000000000000000000000000000000000000000000000002"))
    {}
    
    uint256 getMerkleHash();
    
    bool empty() const;
    void clear();
    
    bool checkConsistency() const;
    
    bool WriteToDisk();
    bool ReadFromDisk(bool check = false);
    
    std::vector<NamedNodeType> flattenTrie() const;
    bool getInfoForName(const std::string& name, CNameValue& claim) const;
    bool getLastTakeoverForName(const std::string& name, int& lastTakeoverHeight) const;

    NameTrieForNameType getClaimsForName(const std::string& name) const;
    CAmount getEffectiveAmountForClaim(const std::string& name, uint160 claimId) const;   
 
    bool queueEmpty() const;
    bool supportEmpty() const;
    bool supportQueueEmpty() const;
    bool expirationQueueEmpty() const;
    bool supportExpirationQueueEmpty() const;
    
    void setExpirationTime(int t);
    
    bool getQueueRow(int nHeight, NameQueueRowType& row) const;
    bool getQueueNameRow(const std::string& name, NamequeueNameRowType& row) const;
    bool getExpirationQueueRow(int nHeight, expirationNameQueueRowType& row) const;
    bool getSupportNode(std::string name, supportNameMapEntryType& node) const;
    bool getSupportQueueRow(int nHeight, NamesupportQueueRowType& row) const;
    bool getSupportQueueNameRow(const std::string& name, NamequeueNameRowType& row) const;
    bool getSupportExpirationQueueRow(int nHeight, expirationNameQueueRowType& row) const;
    
    bool haveClaim(const std::string& name, const COutPoint& outPoint) const;
    bool haveClaimInQueue(const std::string& name, const COutPoint& outPoint,
                          int& nValidAtHeight) const;
    
    bool haveSupport(const std::string& name, const COutPoint& outPoint) const;
    bool haveSupportInQueue(const std::string& name, const COutPoint& outPoint,
                            int& nValidAtHeight) const;
    
    unsigned int getTotalNamesInTrie() const;
    unsigned int getTotalClaimsInTrie() const;
    CAmount getTotalValueOfClaimsInTrie(bool fControllingOnly) const;
    
    friend class CNameTrieCache;
    
    // leveldb 
    CDBWrapper db;
    int nCurrentHeight;
    int nExpirationTime;
    int nProportionalDelayFactor;
    const CNameTrieNode* getNodeForName(const std::string& name) const;

private:
    void clear(CNameTrieNode* current);

    
    bool update(NodenodeCacheType& cache, hashMapType& hashes,
                std::map<std::string, int>& takeoverHeights,
                const uint256& hashBlock, nameQueueType& queueCache,
                NamequeueNameType& queueNameCache,
                expirationNameQueueType& expirationQueueCache, int nNewHeight,
                NamesupportMapType& supportCache,
                supportNameQueueType& supportQueueCache,
                NamequeueNameType& supportQueueNameCache,
                expirationNameQueueType& supportExpirationQueueCache);
    bool updateName(const std::string& name, CNameTrieNode* updatedNode);
    bool updateHash(const std::string& name, uint256& hash);
    bool updateTakeoverHeight(const std::string& name, int nTakeoverHeight);
    bool recursiveNullify(CNameTrieNode* node, std::string& name);
    
    bool recursiveCheckConsistency(const CNameTrieNode* node) const;
    
    bool InsertFromDisk(const std::string& name, CNameTrieNode* node);
    
    unsigned int getTotalNamesRecursive(const CNameTrieNode* current) const;
    unsigned int getTotalClaimsRecursive(const CNameTrieNode* current) const;
    CAmount getTotalValueOfClaimsRecursive(const CNameTrieNode* current,
                                           bool fControllingOnly) const;
    bool recursiveFlattenTrie(const std::string& name,
                              const CNameTrieNode* current,
                              std::vector<NamedNodeType>& nodes) const;
    
    void markNodeDirty(const std::string& name, CNameTrieNode* node);
    void updateQueueRow(int nHeight, NameQueueRowType& row);
    void updateQueueNameRow(const std::string& name,
                            NamequeueNameRowType& row);
    void updateExpirationRow(int nHeight, expirationNameQueueRowType& row);
    void updateSupportMap(const std::string& name, supportNameMapEntryType& node);
    void updateSupportQueue(int nHeight, NamesupportQueueRowType& row);
    void updateSupportNameQueue(const std::string& name,
                                NamequeueNameRowType& row);
    void updateSupportExpirationQueue(int nHeight, expirationNameQueueRowType& row);
    
    void BatchWriteNode(CDBBatch& batch, const std::string& name,
                        const CNameTrieNode* pNode) const;
    void BatchEraseNode(CDBBatch& batch, const std::string& nome) const;
    void BatchWriteQueueRows(CDBBatch& batch);
    void BatchWriteQueueNameRows(CDBBatch& batch);
    void BatchWriteExpirationQueueRows(CDBBatch& batch);
    void BatchWriteSupportNodes(CDBBatch& batch);
    void BatchWriteSupportQueueRows(CDBBatch& batch);
    void BatchWriteSupportQueueNameRows(CDBBatch& batch);
    void BatchWriteSupportExpirationQueueRows(CDBBatch& batch);
    template<typename K> bool keyTypeEmpty(char key, K& dummy) const;
    
    CNameTrieNode root;
    uint256 hashBlock;
    
    nameQueueType dirtyQueueRows;
    NamequeueNameType dirtyQueueNameRows;
    expirationNameQueueType dirtyExpirationQueueRows;
    
    supportNameQueueType dirtySupportQueueRows;
    NamequeueNameType dirtySupportQueueNameRows;
    expirationNameQueueType dirtySupportExpirationQueueRows;
    
    NodenodeCacheType dirtyNodes;
    NamesupportMapType dirtySupportNodes;
};

class CNameTrieProofNode
{
public:
    CNameTrieProofNode() {};
    CNameTrieProofNode(std::vector<std::pair<unsigned char, uint256> > children,
                        bool hasValue, uint256 valHash)
        : children(children), hasValue(hasValue), valHash(valHash)
        {};
    std::vector<std::pair<unsigned char, uint256> > children;
    bool hasValue;
    uint256 valHash;
};

class CNameTrieProof
{
public:
    CNameTrieProof() {};
    CNameTrieProof(std::vector<CNameTrieProofNode> nodes, bool hasValue, COutPoint outPoint, int nHeightOfLastTakeover) : nodes(nodes), hasValue(hasValue), outPoint(outPoint), nHeightOfLastTakeover(nHeightOfLastTakeover) {}
    std::vector<CNameTrieProofNode> nodes;
    bool hasValue;
    COutPoint outPoint;
    int nHeightOfLastTakeover;
};

class CNameTrieCache
{
public:
    CNameTrieCache(CNameTrie* base, bool fRequireTakeoverHeights = true)
                    : base(base),
                      fRequireTakeoverHeights(fRequireTakeoverHeights)
    {
        assert(base);
        nCurrentHeight = base->nCurrentHeight;
    }
    
    uint256 getMerkleHash() const;
    
    bool empty() const;
    bool flush();
    bool dirty() const { return !dirtyHashes.empty(); }
    
    bool addClaim(const std::string& name, const COutPoint& outPoint,
                  uint160 claimId, CAmount nAmount, int nHeight,std::string addr) const;
    bool undoAddClaim(const std::string& name, const COutPoint& outPoint,
                      int nHeight) const;
    bool spendClaim(const std::string& name, const COutPoint& outPoint,
                    int nHeight, int& nValidAtHeight) const;
    bool undoSpendClaim(const std::string& name, const COutPoint& outPoint,
                        uint160 claimId, CAmount nAmount, int nHeight,
                        int nValidAtHeight,std::string addr) const;
    
    bool addSupport(const std::string& name, const COutPoint& outPoint,
                    CAmount nAmount, uint160 supportedClaimId,
                    int nHeight) const;
    bool undoAddSupport(const std::string& name, const COutPoint& outPoint,
                        int nHeight) const;
    bool spendSupport(const std::string& name, const COutPoint& outPoint,
                      int nHeight, int& nValidAtHeight) const;
    bool undoSpendSupport(const std::string& name, const COutPoint& outPoint,
                          uint160 supportedClaimId, CAmount nAmount,
                          int nHeight, int nValidAtHeight) const;
    
    uint256 getBestBlock();
    void setBestBlock(const uint256& hashBlock);

    bool incrementBlock(insertNameUndoType& insertUndo,
                        NameQueueRowType& expireUndo,
                        insertNameUndoType& insertSupportUndo,
                        NamesupportQueueRowType& expireSupportUndo,
                        std::vector<std::pair<std::string, int> >& takeoverHeightUndo) const;
    bool decrementBlock(insertNameUndoType& insertUndo,
                        NameQueueRowType& expireUndo,
                        insertNameUndoType& insertSupportUndo,
                        NamesupportQueueRowType& expireSupportUndo,
                        std::vector<std::pair<std::string, int> >& takeoverHeightUndo) const;
    
    ~CNameTrieCache() { clear(); }
    
    bool insertClaimIntoTrie(const std::string& name, CNameValue claim,
                             bool fCheckTakeover = false) const;
    bool removeClaimFromTrie(const std::string& name, const COutPoint& outPoint,
                             CNameValue& claim,
                             bool fCheckTakeover = false) const;
    CNameTrieProof getProofForName(const std::string& name) const;

    bool finalizeDecrement() const;
private:
    CNameTrie* base;

    bool fRequireTakeoverHeights;

    mutable NodenodeCacheType cache;
    mutable NodenodeCacheType block_originals;
    mutable std::set<std::string> dirtyHashes;
    mutable hashMapType cacheHashes;
    mutable nameQueueType claimQueueCache;
    mutable NamequeueNameType claimQueueNameCache;
    mutable expirationNameQueueType expirationQueueCache;
    mutable NamesupportMapType supportCache;
    mutable supportNameQueueType supportQueueCache;
    mutable NamequeueNameType supportQueueNameCache;
    mutable expirationNameQueueType supportExpirationQueueCache;
    mutable std::set<std::string> namesToCheckForTakeover;
    mutable std::map<std::string, int> cacheTakeoverHeights; 
    mutable int nCurrentHeight; // Height of the block that is being worked on, which is
                                // one greater than the height of the chain's tip
    
    uint256 hashBlock;
    
    uint256 computeHash() const;
    
    bool reorderTrieNode(const std::string& name, bool fCheckTakeover) const;
    bool recursiveComputeMerkleHash(CNameTrieNode* tnCurrent,
                                    std::string sPos) const;
    bool recursivePruneName(CNameTrieNode* tnCurrent, unsigned int nPos,
                            std::string sName,
                            bool* pfNullified = NULL) const;
    
    bool clear() const;
    
    bool removeClaim(const std::string& name, const COutPoint& outPoint,
                     int nHeight, int& nValidAtHeight, bool fCheckTakeover) const;
    
    bool addClaimToQueues(const std::string& name, CNameValue& claim) const;
    bool removeClaimFromQueue(const std::string& name, const COutPoint& outPoint,
                              CNameValue& claim) const;
    void addToExpirationQueue(int nExpirationHeight, NameOutPointType& entry) const;
    void removeFromExpirationQueue(const std::string& name, const COutPoint& outPoint,
                                   int nHeight) const;
    
    nameQueueType::iterator getQueueCacheRow(int nHeight,
                                              bool createIfNotExists) const;
    NamequeueNameType::iterator getQueueCacheNameRow(const std::string& name,
                                                 bool createIfNotExists) const;
    expirationNameQueueType::iterator getExpirationQueueCacheRow(int nHeight,
                                                             bool createIfNotExists) const;
    
    bool removeSupport(const std::string& name, const COutPoint& outPoint,
                       int nHeight, int& nValidAtHeight,
                       bool fCheckTakeover) const;
    bool removeSupportFromMap(const std::string& name, const COutPoint& outPoint,
                              CSupportNameValue& support,
                              bool fCheckTakeover) const;
    
    bool insertSupportIntoMap(const std::string& name,
                              CSupportNameValue support,
                              bool fCheckTakeover) const;
    
    supportNameQueueType::iterator getSupportQueueCacheRow(int nHeight,
                                                       bool createIfNotExists) const;
    NamequeueNameType::iterator getSupportQueueCacheNameRow(const std::string& name,
                                                                 bool createIfNotExists) const;
    expirationNameQueueType::iterator getSupportExpirationQueueCacheRow(int nHeight,
                                                                     bool createIfNotExists) const;

    bool addSupportToQueues(const std::string& name, CSupportNameValue& support) const;
    bool removeSupportFromQueue(const std::string& name, const COutPoint& outPoint,
                                CSupportNameValue& support) const;

    void addSupportToExpirationQueue(int nExpirationHeight,
                                     NameOutPointType& entry) const;
    void removeSupportFromExpirationQueue(const std::string& name,
                                          const COutPoint& outPoint,
                                          int nHeight) const;
    
    bool getSupportsForName(const std::string& name,
                            supportNameMapEntryType& node) const;

    bool getLastTakeoverForName(const std::string& name, int& lastTakeoverHeight) const;
    
    int getDelayForName(const std::string& name) const;

    uint256 getLeafHashForProof(const std::string& currentPosition, unsigned char nodeChar,
                                const CNameTrieNode* currentNode) const;

    CNameTrieNode* addNodeToCache(const std::string& position, CNameTrieNode* original) const;

    bool getOriginalInfoForName(const std::string& name, CNameValue& claim) const;

    int getNumBlocksOfContinuousOwnership(const std::string& name) const;
};

#endif // ULORD_NAMETRIE_H
