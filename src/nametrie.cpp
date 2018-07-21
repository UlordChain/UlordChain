// Copyright (c) 2016-2018 Ulord Foundation Ltd.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "nametrie.h"
#include "coins.h"
#include "hash.h"

#include <boost/scoped_ptr.hpp>
#include <iostream>
#include <algorithm>

std::vector<unsigned char> nameheightToVch(int n)
{
    std::vector<unsigned char> vchHeight;
    vchHeight.resize(8);
    vchHeight[0] = 0;
    vchHeight[1] = 0;
    vchHeight[2] = 0;
    vchHeight[3] = 0;
    vchHeight[4] = n >> 24;
    vchHeight[5] = n >> 16;
    vchHeight[6] = n >> 8;
    vchHeight[7] = n;
    return vchHeight;
}

uint256 namegetValueHash(COutPoint outPoint, int nHeightOfLastTakeover)
{
    CHash256 txHasher;
    txHasher.Write(outPoint.hash.begin(), outPoint.hash.size());
    std::vector<unsigned char> vchtxHash(txHasher.OUTPUT_SIZE);
    txHasher.Finalize(&(vchtxHash[0]));
        
    CHash256 nOutHasher;
    std::stringstream ss;
    ss << outPoint.n;
    std::string snOut = ss.str();
    nOutHasher.Write((unsigned char*) snOut.data(), snOut.size());
    std::vector<unsigned char> vchnOutHash(nOutHasher.OUTPUT_SIZE);
    nOutHasher.Finalize(&(vchnOutHash[0]));

    CHash256 takeoverHasher;
    std::vector<unsigned char> vchTakeoverHeightToHash = nameheightToVch(nHeightOfLastTakeover);
    takeoverHasher.Write(vchTakeoverHeightToHash.data(), vchTakeoverHeightToHash.size());
    std::vector<unsigned char> vchTakeoverHash(takeoverHasher.OUTPUT_SIZE);
    takeoverHasher.Finalize(&(vchTakeoverHash[0]));

    CHash256 hasher;
    hasher.Write(vchtxHash.data(), vchtxHash.size());
    hasher.Write(vchnOutHash.data(), vchnOutHash.size());
    hasher.Write(vchTakeoverHash.data(), vchTakeoverHash.size());
    std::vector<unsigned char> vchHash(hasher.OUTPUT_SIZE);
    hasher.Finalize(&(vchHash[0]));
    
    uint256 valueHash(vchHash);
    return valueHash;
}

bool CNameTrieNode::insertClaim(CNameValue claim)
{
    LogPrintf("%s: Inserting %s:%d (amount: %d)  into the claim trie\n", __func__, claim.outPoint.hash.ToString(), claim.outPoint.n, claim.nAmount);
    claims.push_back(claim);
    return true;
}

bool CNameTrieNode::removeClaim(const COutPoint& outPoint, CNameValue& claim)
{
    LogPrintf("%s: Removing txid: %s, nOut: %d from the claim trie\n", __func__, outPoint.hash.ToString(), outPoint.n);

    std::vector<CNameValue>::iterator itClaims;
    for (itClaims = claims.begin(); itClaims != claims.end(); ++itClaims)
    {
        if (itClaims->outPoint == outPoint)
        {
            std::swap(claim, *itClaims);
            break;
        }
    }
    if (itClaims != claims.end())
    {
        claims.erase(itClaims);
    }
    else
    {
        LogPrintf("CNameTrieNode::%s() : asked to remove a claim that doesn't exist\n", __func__);
        LogPrintf("CNameTrieNode::%s() : claims that do exist:\n", __func__);
        for (unsigned int i = 0; i < claims.size(); i++)
        {
            LogPrintf("\ttxhash: %s, nOut: %d:\n", claims[i].outPoint.hash.ToString(), claims[i].outPoint.n);
        }
        return false;
    }
    return true;
}

bool CNameTrieNode::getBestClaim(CNameValue& claim) const
{
    if (claims.empty())
    {
        return false;
    }
    else
    {
        claim = claims.front();
        return true;
    }
}

bool CNameTrieNode::haveClaim(const COutPoint& outPoint) const
{
    for (std::vector<CNameValue>::const_iterator itclaim = claims.begin(); itclaim != claims.end(); ++itclaim)
    {
        if (itclaim->outPoint == outPoint)
            return true;
    }
    return false;
}

void CNameTrieNode::reorderClaims(supportNameMapEntryType& supports)
{
    std::vector<CNameValue>::iterator itclaim;
    
    for (itclaim = claims.begin(); itclaim != claims.end(); ++itclaim)
    {
        itclaim->nEffectiveAmount = itclaim->nAmount;
    }

    for (supportNameMapEntryType::iterator itsupport = supports.begin(); itsupport != supports.end(); ++itsupport)
    {
        for (itclaim = claims.begin(); itclaim != claims.end(); ++itclaim)
        {
            if (itsupport->supportedClaimId == itclaim->claimId)
            {
                itclaim->nEffectiveAmount += itsupport->nAmount;
                break;
            }
        }
    }
    
    std::make_heap(claims.begin(), claims.end());
}

uint256 CNameTrie::getMerkleHash()
{
    return root.hash;
}

bool CNameTrie::empty() const
{
    return root.empty();
}

template<typename K> bool CNameTrie::keyTypeEmpty(char keyType, K& dummy) const
{
    boost::scoped_ptr<CDBIterator> pcursor(const_cast<CDBWrapper*>(&db)->NewIterator());
    pcursor->SeekToFirst();
    
    while (pcursor->Valid())
    {
        std::pair<char, K> key;
        if (pcursor->GetKey(key))
        {
            if (key.first == keyType)
            {
                return false;
            }
        }
        else
        {
            break;
        }
        pcursor->Next();
    }
    return true;
}

bool CNameTrie::queueEmpty() const
{
    for (nameQueueType::const_iterator itRow = dirtyQueueRows.begin(); itRow != dirtyQueueRows.end(); ++itRow)
    {
        if (!itRow->second.empty())
            return false;
    }
    int dummy;
    return keyTypeEmpty(CLAIM_QUEUE_ROW, dummy);
}

bool CNameTrie::expirationQueueEmpty() const
{
    for (expirationNameQueueType::const_iterator itRow = dirtyExpirationQueueRows.begin(); itRow != dirtyExpirationQueueRows.end(); ++itRow)
    {
        if (!itRow->second.empty())
            return false;
    }
    int dummy;
    return keyTypeEmpty(EXP_QUEUE_ROW, dummy);
}

bool CNameTrie::supportEmpty() const
{
    for (NamesupportMapType::const_iterator itNode = dirtySupportNodes.begin(); itNode != dirtySupportNodes.end(); ++itNode)
    {
        if (!itNode->second.empty())
            return false;
    }
    std::string dummy;
    return keyTypeEmpty(SUPPORT, dummy);
}

bool CNameTrie::supportQueueEmpty() const
{
    for (supportNameQueueType::const_iterator itRow = dirtySupportQueueRows.begin(); itRow != dirtySupportQueueRows.end(); ++itRow)
    {
        if (!itRow->second.empty())
            return false;
    }
    int dummy;
    return keyTypeEmpty(SUPPORT_QUEUE_ROW, dummy);
}

void CNameTrie::setExpirationTime(int t)
{
    nExpirationTime = t;
}

void CNameTrie::clear()
{
    clear(&root);
}

void CNameTrie::clear(CNameTrieNode* current)
{
    for (nodeNameMapType::const_iterator itchildren = current->children.begin(); itchildren != current->children.end(); ++itchildren)
    {
        clear(itchildren->second);
        delete itchildren->second;
    }
}

bool CNameTrie::haveClaim(const std::string& name, const COutPoint& outPoint) const
{
    const CNameTrieNode* current = &root;
    for (std::string::const_iterator itname = name.begin(); itname != name.end(); ++itname)
    {
        nodeNameMapType::const_iterator itchildren = current->children.find(*itname);
        if (itchildren == current->children.end())
            return false;
        current = itchildren->second;
    }
    return current->haveClaim(outPoint);
}

bool CNameTrie::haveSupport(const std::string& name, const COutPoint& outPoint) const
{
    supportNameMapEntryType node;
    if (!getSupportNode(name, node))
    {
        return false;
    }
    for (supportNameMapEntryType::const_iterator itnode = node.begin(); itnode != node.end(); ++itnode)
    {
        if (itnode->outPoint == outPoint)
            return true;
    }
    return false;
}

bool CNameTrie::haveClaimInQueue(const std::string& name, const COutPoint& outPoint, int& nValidAtHeight) const
{
    NamequeueNameRowType nameRow;
    if (!getQueueNameRow(name, nameRow))
    {
        return false;
    }
    NamequeueNameRowType::const_iterator itNameRow;
    for (itNameRow = nameRow.begin(); itNameRow != nameRow.end(); ++itNameRow)
    {
        if (itNameRow->outPoint == outPoint)
        {
            nValidAtHeight = itNameRow->nHeight;
            break;
        }
    }
    if (itNameRow == nameRow.end())
    {
        return false;
    }
    NameQueueRowType row;
    if (getQueueRow(nValidAtHeight, row))
    {
        for (NameQueueRowType::const_iterator itRow = row.begin(); itRow != row.end(); ++itRow)
        {
            if (itRow->first == name && itRow->second.outPoint == outPoint)
            {
                if (itRow->second.nValidAtHeight != nValidAtHeight)
                {
                    LogPrintf("%s: An inconsistency was found in the claim queue. Please report this to the developers:\nDifferent nValidAtHeight between named queue and height queue\n: name: %s, txid: %s, nOut: %d, nValidAtHeight in named queue: %d, nValidAtHeight in height queue: %d current height: %d\n", __func__, name, outPoint.hash.GetHex(), outPoint.n, nValidAtHeight, itRow->second.nValidAtHeight, nCurrentHeight);
                }
                return true;
            }
        }
    }
    LogPrintf("%s: An inconsistency was found in the claim queue. Please report this to the developers:\nFound in named queue but not in height queue: name: %s, txid: %s, nOut: %d, nValidAtHeight: %d, current height: %d\n", __func__, name, outPoint.hash.GetHex(), outPoint.n, nValidAtHeight, nCurrentHeight);
    return false;
}

bool CNameTrie::haveSupportInQueue(const std::string& name, const COutPoint& outPoint, int& nValidAtHeight) const
{
    NamequeueNameRowType nameRow;
    if (!getSupportQueueNameRow(name, nameRow))
    {
        return false;
    }
    NamequeueNameRowType::const_iterator itNameRow;
    for (itNameRow = nameRow.begin(); itNameRow != nameRow.end(); ++itNameRow)
    {
        if (itNameRow->outPoint == outPoint)
        {
	    // Height assignment
            nValidAtHeight = itNameRow->nHeight;
            break;
        }
    }
    if (itNameRow == nameRow.end())
    {
        return false;
    }
    NamesupportQueueRowType row;
    if (getSupportQueueRow(nValidAtHeight, row))
    {
        for (NamesupportQueueRowType::const_iterator itRow = row.begin(); itRow != row.end(); ++itRow)
        {
            if (itRow->first == name && itRow->second.outPoint == outPoint)
            {
                if (itRow->second.nValidAtHeight != nValidAtHeight)
                {
                    LogPrintf("%s: An inconsistency was found in the support queue. Please report this to the developers:\nDifferent nValidAtHeight between named queue and height queue\n: name: %s, txid: %s, nOut: %d, nValidAtHeight in named queue: %d, nValidAtHeight in height queue: %d current height: %d\n", __func__, name, outPoint.hash.GetHex(), outPoint.n, nValidAtHeight, itRow->second.nValidAtHeight, nCurrentHeight);
                }
                return true;
            }
        }
    }
    LogPrintf("%s: An inconsistency was found in the claim queue. Please report this to the developers:\nFound in named queue but not in height queue: name: %s, txid: %s, nOut: %d, nValidAtHeight: %d, current height: %d\n", __func__, name, outPoint.hash.GetHex(), outPoint.n, nValidAtHeight, nCurrentHeight);
    return false;
}

unsigned int CNameTrie::getTotalNamesInTrie() const
{
    if (empty())
        return 0;
    const CNameTrieNode* current = &root;
    return getTotalNamesRecursive(current);
}

unsigned int CNameTrie::getTotalNamesRecursive(const CNameTrieNode* current) const
{
    unsigned int names_in_subtrie = 0;
    if (!(current->claims.empty()))
        names_in_subtrie += 1;
    for (nodeNameMapType::const_iterator it = current->children.begin(); it != current->children.end(); ++it)
    {
        names_in_subtrie += getTotalNamesRecursive(it->second);
    }
    return names_in_subtrie;
}

unsigned int CNameTrie::getTotalClaimsInTrie() const
{
    if (empty())
        return 0;
    const CNameTrieNode* current = &root;
    return getTotalClaimsRecursive(current);
}

unsigned int CNameTrie::getTotalClaimsRecursive(const CNameTrieNode* current) const
{
    unsigned int claims_in_subtrie = current->claims.size();
    for (nodeNameMapType::const_iterator it = current->children.begin(); it != current->children.end(); ++it)
    {
        claims_in_subtrie += getTotalClaimsRecursive(it->second);
    }
    return claims_in_subtrie;
}

CAmount CNameTrie::getTotalValueOfClaimsInTrie(bool fControllingOnly) const
{
    if (empty())
        return 0;
    const CNameTrieNode* current = &root;
    return getTotalValueOfClaimsRecursive(current, fControllingOnly);
}

CAmount CNameTrie::getTotalValueOfClaimsRecursive(const CNameTrieNode* current, bool fControllingOnly) const
{
    CAmount value_in_subtrie = 0;
    for (std::vector<CNameValue>::const_iterator itclaim = current->claims.begin(); itclaim != current->claims.end(); ++itclaim)
    {
        value_in_subtrie += itclaim->nAmount;
        if (fControllingOnly)
            break;
    }
    for (nodeNameMapType::const_iterator itchild = current->children.begin(); itchild != current->children.end(); ++itchild)
     {
         value_in_subtrie += getTotalValueOfClaimsRecursive(itchild->second, fControllingOnly);
     }
     return value_in_subtrie;
}

bool CNameTrie::recursiveFlattenTrie(const std::string& name, const CNameTrieNode* current, std::vector<NamedNodeType>& nodes) const
{
    NamedNodeType node(name, *current);
    nodes.push_back(node);
    for (nodeNameMapType::const_iterator it = current->children.begin(); it != current->children.end(); ++it)
    {
        std::stringstream ss;
        ss << name << it->first;
        if (!recursiveFlattenTrie(ss.str(), it->second, nodes))
            return false;
    }
    return true;
}

std::vector<NamedNodeType> CNameTrie::flattenTrie() const
{
    std::vector<NamedNodeType> nodes;
    if (!recursiveFlattenTrie("", &root, nodes))
        LogPrintf("%s: Something went wrong flattening the trie", __func__);
    return nodes;
}

const CNameTrieNode* CNameTrie::getNodeForName(const std::string& name) const
{
    const CNameTrieNode* current = &root;
    for (std::string::const_iterator itname = name.begin(); itname != name.end(); ++itname)
    {
        nodeNameMapType::const_iterator itchildren = current->children.find(*itname);
        if (itchildren == current->children.end())
            return NULL;
        current = itchildren->second;
    }
    return current;
}

bool CNameTrie::getInfoForName(const std::string& name, CNameValue& claim) const
{
    const CNameTrieNode* current = getNodeForName(name);
    if (current)
    {
        return current->getBestClaim(claim);
    }
    return false;
}

bool CNameTrie::getLastTakeoverForName(const std::string& name, int& lastTakeoverHeight) const
{
    const CNameTrieNode* current = getNodeForName(name);
    if (current && !current->claims.empty())
    {
        lastTakeoverHeight = current->nHeightOfLastTakeover;
        return true;
    }
    return false;
}

NameTrieForNameType CNameTrie::getClaimsForName(const std::string& name) const
{
    std::vector<CNameValue> claims;
    std::vector<CSupportNameValue> supports;
    int nLastTakeoverHeight = 0;
    const CNameTrieNode* current = getNodeForName(name);
    if (current)
    {
        if (!current->claims.empty())
        {
            nLastTakeoverHeight = current->nHeightOfLastTakeover;
        }
        for (std::vector<CNameValue>::const_iterator itClaims = current->claims.begin(); itClaims != current->claims.end(); ++itClaims)
        {
            claims.push_back(*itClaims);
        }
    }
    supportNameMapEntryType supportNode;
    if (getSupportNode(name, supportNode))
    {
        for (std::vector<CSupportNameValue>::const_iterator itSupports = supportNode.begin(); itSupports != supportNode.end(); ++itSupports)
        {
            supports.push_back(*itSupports);
        }
    }
    NamequeueNameRowType namedClaimRow;
    if (getQueueNameRow(name, namedClaimRow))
    {
        for (NamequeueNameRowType::const_iterator itClaimsForName = namedClaimRow.begin(); itClaimsForName != namedClaimRow.end(); ++itClaimsForName)
        {
            NameQueueRowType claimRow;
            if (getQueueRow(itClaimsForName->nHeight, claimRow))
            {
                for (NameQueueRowType::const_iterator itClaimRow = claimRow.begin(); itClaimRow != claimRow.end(); ++itClaimRow)
                 {
                     if (itClaimRow->first == name && itClaimRow->second.outPoint == itClaimsForName->outPoint)
                     {
                         claims.push_back(itClaimRow->second);
                         break;
                     }
                 }
            }
        }
    }
    NamequeueNameRowType namedSupportRow;
    if (getSupportQueueNameRow(name, namedSupportRow))
    {
        for (NamequeueNameRowType::const_iterator itSupportsForName = namedSupportRow.begin(); itSupportsForName != namedSupportRow.end(); ++itSupportsForName)
        {
            NamesupportQueueRowType supportRow;
            if (getSupportQueueRow(itSupportsForName->nHeight, supportRow))
            {
                for (NamesupportQueueRowType::const_iterator itSupportRow = supportRow.begin(); itSupportRow != supportRow.end(); ++itSupportRow)
                {
                    if (itSupportRow->first == name && itSupportRow->second.outPoint == itSupportsForName->outPoint)
                    {
                        supports.push_back(itSupportRow->second);
                        break;
                    }
                }
            }
        }
    }
    NameTrieForNameType allClaims(claims, supports, nLastTakeoverHeight);
    return allClaims;
}

//return effective amount form claim, retuns 0 if claim is not found
CAmount CNameTrie::getEffectiveAmountForClaim(const std::string& name, uint160 claimId) const
{
	NameTrieForNameType claims = getClaimsForName(name);
	CAmount effectiveAmount = 0;
	bool claim_found = false;
	for (std::vector<CNameValue>::iterator it=claims.claims.begin(); it!=claims.claims.end(); ++it)
	{
		if (it->claimId == claimId && it->nValidAtHeight < nCurrentHeight)
			effectiveAmount += it->nAmount;
			claim_found = true;
			break;
	}
	if (!claim_found)
		return effectiveAmount;

	for (std::vector<CSupportNameValue>::iterator it=claims.supports.begin(); it!=claims.supports.end(); ++it)
	{
		if (it->supportedClaimId == claimId && it->nValidAtHeight < nCurrentHeight)
			effectiveAmount += it->nAmount;
	}
	return effectiveAmount;

}

bool CNameTrie::checkConsistency() const
{
    if (empty())
        return true;
    return recursiveCheckConsistency(&root);
}

bool CNameTrie::recursiveCheckConsistency(const CNameTrieNode* node) const
{
    std::vector<unsigned char> vchToHash;

    for (nodeNameMapType::const_iterator it = node->children.begin(); it != node->children.end(); ++it)
    {
        if (recursiveCheckConsistency(it->second))
        {
            vchToHash.push_back(it->first);
            vchToHash.insert(vchToHash.end(), it->second->hash.begin(), it->second->hash.end());
        }
        else
            return false;
    }

    CNameValue claim;
    bool hasClaim = node->getBestClaim(claim);

    if (hasClaim)
    {
        uint256 valueHash = namegetValueHash(claim.outPoint, node->nHeightOfLastTakeover);
        vchToHash.insert(vchToHash.end(), valueHash.begin(), valueHash.end());
    }

    CHash256 hasher;
    std::vector<unsigned char> vchHash(hasher.OUTPUT_SIZE);
    hasher.Write(vchToHash.data(), vchToHash.size());
    hasher.Finalize(&(vchHash[0]));
    uint256 calculatedHash(vchHash);
    return calculatedHash == node->hash;
}

bool CNameTrie::getQueueRow(int nHeight, NameQueueRowType& row) const
{
    nameQueueType::const_iterator itQueueRow = dirtyQueueRows.find(nHeight);
    if (itQueueRow != dirtyQueueRows.end())
    {
        row = itQueueRow->second;
        return true;
    }
    return db.Read(std::make_pair(CLAIM_QUEUE_ROW, nHeight), row);
}

bool CNameTrie::getQueueNameRow(const std::string& name, NamequeueNameRowType& row) const
{
    NamequeueNameType::const_iterator itQueueNameRow = dirtyQueueNameRows.find(name);
    if (itQueueNameRow != dirtyQueueNameRows.end())
    {
        row = itQueueNameRow->second;
        return true;
    }
    return db.Read(std::make_pair(CLAIM_QUEUE_NAME_ROW, name), row);
}

bool CNameTrie::getExpirationQueueRow(int nHeight, expirationNameQueueRowType& row) const
{
    expirationNameQueueType::const_iterator itQueueRow = dirtyExpirationQueueRows.find(nHeight);
    if (itQueueRow != dirtyExpirationQueueRows.end())
    {
        row = itQueueRow->second;
        return true;
    }
    return db.Read(std::make_pair(EXP_QUEUE_ROW, nHeight), row);
}

void CNameTrie::updateQueueRow(int nHeight, NameQueueRowType& row)
{
    nameQueueType::iterator itQueueRow = dirtyQueueRows.find(nHeight);
    if (itQueueRow == dirtyQueueRows.end())
    {
        NameQueueRowType newRow;
        std::pair<nameQueueType::iterator, bool> ret;
        ret = dirtyQueueRows.insert(std::pair<int, NameQueueRowType >(nHeight, newRow));
        if(!ret.second)
	{	
            LogPrintf("ret.second is error %d,%s\n",__LINE__,__func__);
	    return;	
	}	
        itQueueRow = ret.first;
    }
    itQueueRow->second.swap(row);
}

void CNameTrie::updateQueueNameRow(const std::string& name, NamequeueNameRowType& row)
{
    NamequeueNameType::iterator itQueueRow = dirtyQueueNameRows.find(name);
    if (itQueueRow == dirtyQueueNameRows.end())
    {
        NamequeueNameRowType newRow;
        std::pair<NamequeueNameType::iterator, bool> ret;
        ret = dirtyQueueNameRows.insert(std::pair<std::string, NamequeueNameRowType>(name, newRow));
        if(!ret.second)
	{
            LogPrintf("ret.second is error %d,%s\n",__LINE__,__func__);
	    return; 	
	}	
        itQueueRow = ret.first;
    }
    itQueueRow->second.swap(row);
}

void CNameTrie::updateExpirationRow(int nHeight, expirationNameQueueRowType& row)
{
    expirationNameQueueType::iterator itQueueRow = dirtyExpirationQueueRows.find(nHeight);
    if (itQueueRow == dirtyExpirationQueueRows.end())
    {
        expirationNameQueueRowType newRow;
        std::pair<expirationNameQueueType::iterator, bool> ret;
        ret = dirtyExpirationQueueRows.insert(std::pair<int, expirationNameQueueRowType >(nHeight, newRow));
        if(!ret.second)
	{
	   LogPrintf("ret.second is error %d,%s\n",__LINE__,__func__);
	   return;
	}
        itQueueRow = ret.first;
    }
    itQueueRow->second.swap(row);
}

void CNameTrie::updateSupportMap(const std::string& name, supportNameMapEntryType& node)
{
    NamesupportMapType::iterator itNode = dirtySupportNodes.find(name);
    if (itNode == dirtySupportNodes.end())
    {
        supportNameMapEntryType newNode;
        std::pair<NamesupportMapType::iterator, bool> ret;
        ret = dirtySupportNodes.insert(std::pair<std::string, supportNameMapEntryType>(name, newNode));
        if(!ret.second)
	{
            LogPrintf("ret.second is error %d,%s\n",__LINE__,__func__);
	     return;	
	}
        itNode = ret.first;
    }
    itNode->second.swap(node);
}

void CNameTrie::updateSupportQueue(int nHeight, NamesupportQueueRowType& row)
{
    supportNameQueueType::iterator itQueueRow = dirtySupportQueueRows.find(nHeight);
    if (itQueueRow == dirtySupportQueueRows.end())
    {
        NamesupportQueueRowType newRow;
        std::pair<supportNameQueueType::iterator, bool> ret;
        ret = dirtySupportQueueRows.insert(std::pair<int, NamesupportQueueRowType >(nHeight, newRow));
        if(!ret.second)
	{
            LogPrintf("ret.second is error %d,%s\n",__LINE__,__func__);
	    return;
	}
        itQueueRow = ret.first;
    }
    itQueueRow->second.swap(row);
}

void CNameTrie::updateSupportNameQueue(const std::string& name, NamequeueNameRowType& row)
{
    NamequeueNameType::iterator itQueueRow = dirtySupportQueueNameRows.find(name);
    if (itQueueRow == dirtySupportQueueNameRows.end())
    {
        NamequeueNameRowType newRow;
        std::pair<NamequeueNameType::iterator, bool> ret;
        ret = dirtySupportQueueNameRows.insert(std::pair<std::string, NamequeueNameRowType>(name, newRow));
        if(!ret.second)
	{
            LogPrintf("ret.second is error %d,%s\n",__LINE__,__func__);
	    return;
	}
        itQueueRow = ret.first;
    }
    itQueueRow->second.swap(row);
}

void CNameTrie::updateSupportExpirationQueue(int nHeight, expirationNameQueueRowType& row)
{
    expirationNameQueueType::iterator itQueueRow = dirtySupportExpirationQueueRows.find(nHeight);
    if (itQueueRow == dirtySupportExpirationQueueRows.end())
    {
        expirationNameQueueRowType newRow;
        std::pair<expirationNameQueueType::iterator, bool> ret;
        ret = dirtySupportExpirationQueueRows.insert(std::pair<int, expirationNameQueueRowType >(nHeight, newRow));
        if(!ret.second)
	{
            LogPrintf("ret.second is error %d,%s\n",__LINE__,__func__);
	    return;
	}
        itQueueRow = ret.first;
    }
    itQueueRow->second.swap(row);
}

bool CNameTrie::getSupportNode(std::string name, supportNameMapEntryType& node) const
{
    NamesupportMapType::const_iterator itNode = dirtySupportNodes.find(name);
    if (itNode != dirtySupportNodes.end())
    {
        node = itNode->second;
        return true;
    }
    return db.Read(std::make_pair(SUPPORT, name), node);
}

bool CNameTrie::getSupportQueueRow(int nHeight, NamesupportQueueRowType& row) const
{
    supportNameQueueType::const_iterator itQueueRow = dirtySupportQueueRows.find(nHeight);
    if (itQueueRow != dirtySupportQueueRows.end())
    {
        row = itQueueRow->second;
        return true;
    }
    return db.Read(std::make_pair(SUPPORT_QUEUE_ROW, nHeight), row);
}

bool CNameTrie::getSupportQueueNameRow(const std::string& name, NamequeueNameRowType& row) const
{
    NamequeueNameType::const_iterator itQueueNameRow = dirtySupportQueueNameRows.find(name);
    if (itQueueNameRow != dirtySupportQueueNameRows.end())
    {
        row = itQueueNameRow->second;
        return true;
    }
    return db.Read(std::make_pair(SUPPORT_QUEUE_NAME_ROW, name), row);
}

bool CNameTrie::getSupportExpirationQueueRow(int nHeight, expirationNameQueueRowType& row) const
{
    expirationNameQueueType::const_iterator itQueueRow = dirtySupportExpirationQueueRows.find(nHeight);
    if (itQueueRow != dirtySupportExpirationQueueRows.end())
    {
        row = itQueueRow->second;
        return true;
    }
    return db.Read(std::make_pair(SUPPORT_EXP_QUEUE_ROW, nHeight), row);
}

bool CNameTrie::update(NodenodeCacheType& cache, hashMapType& hashes, std::map<std::string, int>& takeoverHeights, const uint256& hashBlockIn, nameQueueType& queueCache, NamequeueNameType& queueNameCache, expirationNameQueueType& expirationQueueCache, int nNewHeight, NamesupportMapType& supportCache, supportNameQueueType& supportQueueCache, NamequeueNameType& supportQueueNameCache, expirationNameQueueType& supportExpirationQueueCache)
{
    for (NodenodeCacheType::iterator itcache = cache.begin(); itcache != cache.end(); ++itcache)
    {
        if (!updateName(itcache->first, itcache->second))
            return false;
    }
    for (hashMapType::iterator ithash = hashes.begin(); ithash != hashes.end(); ++ithash)
    {
        if (!updateHash(ithash->first, ithash->second))
            return false;
    }
    for (std::map<std::string, int>::iterator itheight = takeoverHeights.begin(); itheight != takeoverHeights.end(); ++itheight)
    {
        if (!updateTakeoverHeight(itheight->first, itheight->second))
            return false;
    }
    for (nameQueueType::iterator itQueueCacheRow = queueCache.begin(); itQueueCacheRow != queueCache.end(); ++itQueueCacheRow)
    {
        updateQueueRow(itQueueCacheRow->first, itQueueCacheRow->second);
    }
    for (NamequeueNameType::iterator itQueueNameCacheRow = queueNameCache.begin(); itQueueNameCacheRow != queueNameCache.end(); ++itQueueNameCacheRow)
    {
        updateQueueNameRow(itQueueNameCacheRow->first, itQueueNameCacheRow->second);
    }
    for (expirationNameQueueType::iterator itExpirationRow = expirationQueueCache.begin(); itExpirationRow != expirationQueueCache.end(); ++itExpirationRow)
    {
        updateExpirationRow(itExpirationRow->first, itExpirationRow->second);
    }
    for (NamesupportMapType::iterator itSupportCache = supportCache.begin(); itSupportCache != supportCache.end(); ++itSupportCache)
    {
        updateSupportMap(itSupportCache->first, itSupportCache->second);
    }
    for (supportNameQueueType::iterator itSupportQueue = supportQueueCache.begin(); itSupportQueue != supportQueueCache.end(); ++itSupportQueue)
    {
        updateSupportQueue(itSupportQueue->first, itSupportQueue->second);
    }
    for (NamequeueNameType::iterator itSupportNameQueue = supportQueueNameCache.begin(); itSupportNameQueue != supportQueueNameCache.end(); ++itSupportNameQueue)
    {
        updateSupportNameQueue(itSupportNameQueue->first, itSupportNameQueue->second);
    }
    for (expirationNameQueueType::iterator itSupportExpirationQueue = supportExpirationQueueCache.begin(); itSupportExpirationQueue != supportExpirationQueueCache.end(); ++itSupportExpirationQueue)
    {
        updateSupportExpirationQueue(itSupportExpirationQueue->first, itSupportExpirationQueue->second);
    }
    hashBlock = hashBlockIn;
    nCurrentHeight = nNewHeight;
    return true;
}

void CNameTrie::markNodeDirty(const std::string &name, CNameTrieNode* node)
{
    std::pair<NodenodeCacheType::iterator, bool> ret;
    ret = dirtyNodes.insert(std::pair<std::string, CNameTrieNode*>(name, node));
    if (ret.second == false)
        ret.first->second = node;
}

bool CNameTrie::updateName(const std::string &name, CNameTrieNode* updatedNode)
{
    CNameTrieNode* current = &root;
    for (std::string::const_iterator itname = name.begin(); itname != name.end(); ++itname)
    {
        nodeNameMapType::iterator itchild = current->children.find(*itname);
        if (itchild == current->children.end())
        {
            if (itname + 1 == name.end())
            {
                CNameTrieNode* newNode = new CNameTrieNode();
                current->children[*itname] = newNode;
                current = newNode;
            }
            else
                return false;
        }
        else
        {
            current = itchild->second;
        }
    }
    if(current == NULL)
    {
        LogPrintf("current is error %d,%s\n",__LINE__,__func__);
	return false;
    }
    current->claims.swap(updatedNode->claims);
    markNodeDirty(name, current);
    for (nodeNameMapType::iterator itchild = current->children.begin(); itchild != current->children.end();)
    {
        nodeNameMapType::iterator itupdatechild = updatedNode->children.find(itchild->first);
        if (itupdatechild == updatedNode->children.end())
        {
            // This character has apparently been deleted, so delete
            // all descendents from this child.
            std::stringstream ss;
            ss << name << itchild->first;
            std::string newName = ss.str();
            if (!recursiveNullify(itchild->second, newName))
                return false;
            current->children.erase(itchild++);
        }
        else
            ++itchild;
    }
    return true;
}

bool CNameTrie::recursiveNullify(CNameTrieNode* node, std::string& name)
{
    if(node == NULL)
    {
        LogPrintf("current is error %d,%s\n",__LINE__,__func__);
	    return false;
    }
    for (nodeNameMapType::iterator itchild = node->children.begin(); itchild != node->children.end(); ++itchild)
    {
        std::stringstream ss;
        ss << name << itchild->first;
        std::string newName = ss.str();
        if (!recursiveNullify(itchild->second, newName))
            return false;
    }
    node->children.clear();
    markNodeDirty(name, NULL);
    delete node;
    return true;
}

bool CNameTrie::updateHash(const std::string& name, uint256& hash)
{
    CNameTrieNode* current = &root;
    for (std::string::const_iterator itname = name.begin(); itname != name.end(); ++itname)
    {
        nodeNameMapType::iterator itchild = current->children.find(*itname);
        if (itchild == current->children.end())
            return false;
        current = itchild->second;
    }
    if(current == NULL)
    {
        LogPrintf("current is error %d,%s\n",__LINE__,__func__);
	    return false;
    }
    current->hash = hash;
    markNodeDirty(name, current);
    return true;
}

bool CNameTrie::updateTakeoverHeight(const std::string& name, int nTakeoverHeight)
{
    CNameTrieNode* current = &root;
    for (std::string::const_iterator itname = name.begin(); itname != name.end(); ++itname)
    {
        nodeNameMapType::iterator itchild = current->children.find(*itname);
        if (itchild == current->children.end())
            return false;
        current = itchild->second;
    }
    if(current == NULL)
    {
        LogPrintf("current is error %d,%s\n",__LINE__,__func__);
	    return false;
    }
    current->nHeightOfLastTakeover = nTakeoverHeight;
    markNodeDirty(name, current);
    return true;
}

void CNameTrie::BatchWriteNode(CDBBatch& batch, const std::string& name, const CNameTrieNode* pNode) const
{
    uint32_t num_claims = 0;
    if (pNode)
        num_claims = pNode->claims.size();
    LogPrintf("%s: Writing %s to disk with %d claims\n", __func__, name, num_claims);
    if (pNode)
        batch.Write(std::make_pair(TRIE_NODE, name), *pNode);
    else
        batch.Erase(std::make_pair(TRIE_NODE, name));
}

void CNameTrie::BatchWriteQueueRows(CDBBatch& batch)
{
    for (nameQueueType::iterator itQueue = dirtyQueueRows.begin(); itQueue != dirtyQueueRows.end(); ++itQueue)
    {
        if (itQueue->second.empty())
        {
            batch.Erase(std::make_pair(CLAIM_QUEUE_ROW, itQueue->first));
        }
        else
        {
            batch.Write(std::make_pair(CLAIM_QUEUE_ROW, itQueue->first), itQueue->second);
        }
    }
}

void CNameTrie::BatchWriteQueueNameRows(CDBBatch& batch)
{
    for (NamequeueNameType::iterator itQueue = dirtyQueueNameRows.begin(); itQueue != dirtyQueueNameRows.end(); ++itQueue)
    {
        if (itQueue->second.empty())
        {
            batch.Erase(std::make_pair(CLAIM_QUEUE_NAME_ROW, itQueue->first));
        }
        else
        {
            batch.Write(std::make_pair(CLAIM_QUEUE_NAME_ROW, itQueue->first), itQueue->second);
        }
    }
}

void CNameTrie::BatchWriteExpirationQueueRows(CDBBatch& batch)
{
    for (expirationNameQueueType::iterator itQueue = dirtyExpirationQueueRows.begin(); itQueue != dirtyExpirationQueueRows.end(); ++itQueue)
    {
        if (itQueue->second.empty())
        {
            batch.Erase(std::make_pair(EXP_QUEUE_ROW, itQueue->first));
        }
        else
        {
            batch.Write(std::make_pair(EXP_QUEUE_ROW, itQueue->first), itQueue->second);
        }
    }
}

void CNameTrie::BatchWriteSupportNodes(CDBBatch& batch)
{
    for (NamesupportMapType::iterator itSupport = dirtySupportNodes.begin(); itSupport != dirtySupportNodes.end(); ++itSupport)
    {
        if (itSupport->second.empty())
        {
            batch.Erase(std::make_pair(SUPPORT, itSupport->first));
        }
        else
        {
            batch.Write(std::make_pair(SUPPORT, itSupport->first), itSupport->second);
        }
    }
}

void CNameTrie::BatchWriteSupportQueueRows(CDBBatch& batch)
{
    for (supportNameQueueType::iterator itQueue = dirtySupportQueueRows.begin(); itQueue != dirtySupportQueueRows.end(); ++itQueue)
    {
        if (itQueue->second.empty())
        {
            batch.Erase(std::make_pair(SUPPORT_QUEUE_ROW, itQueue->first));
        }
        else
        {
            batch.Write(std::make_pair(SUPPORT_QUEUE_ROW, itQueue->first), itQueue->second);
        }
    }
}

void CNameTrie::BatchWriteSupportQueueNameRows(CDBBatch& batch)
{
    for (NamequeueNameType::iterator itQueue = dirtySupportQueueNameRows.begin(); itQueue != dirtySupportQueueNameRows.end(); ++itQueue)
    {
        if (itQueue->second.empty())
        {
            batch.Erase(std::make_pair(SUPPORT_QUEUE_NAME_ROW, itQueue->first));
        }
        else
        {
            batch.Write(std::make_pair(SUPPORT_QUEUE_NAME_ROW, itQueue->first), itQueue->second);
        }
    }
}

void CNameTrie::BatchWriteSupportExpirationQueueRows(CDBBatch& batch)
{
    for (expirationNameQueueType::iterator itQueue = dirtySupportExpirationQueueRows.begin(); itQueue != dirtySupportExpirationQueueRows.end(); ++itQueue)
    {
        if (itQueue->second.empty())
        {
            batch.Erase(std::make_pair(SUPPORT_EXP_QUEUE_ROW, itQueue->first));
        }
        else
        {
            batch.Write(std::make_pair(SUPPORT_EXP_QUEUE_ROW, itQueue->first), itQueue->second);
        }
    }
}

bool CNameTrie::WriteToDisk()
{
    CDBBatch batch(&db.GetObfuscateKey());
    for (NodenodeCacheType::iterator itcache = dirtyNodes.begin(); itcache != dirtyNodes.end(); ++itcache)
        BatchWriteNode(batch, itcache->first, itcache->second);
    dirtyNodes.clear();
    BatchWriteQueueRows(batch);
    dirtyQueueRows.clear();
    BatchWriteQueueNameRows(batch);
    dirtyQueueNameRows.clear();
    BatchWriteExpirationQueueRows(batch);
    dirtyExpirationQueueRows.clear();
    BatchWriteSupportNodes(batch);
    dirtySupportNodes.clear();
    BatchWriteSupportQueueRows(batch);
    dirtySupportQueueRows.clear();
    BatchWriteSupportQueueNameRows(batch);
    dirtySupportQueueNameRows.clear();
    BatchWriteSupportExpirationQueueRows(batch);
    dirtySupportExpirationQueueRows.clear();
    batch.Write(HASH_BLOCK, hashBlock);
    batch.Write(CURRENT_HEIGHT, nCurrentHeight);
    return db.WriteBatch(batch);
}

bool CNameTrie::InsertFromDisk(const std::string& name, CNameTrieNode* node)
{
    if (name.size() == 0)
    {
        root = *node;
        return true;
    }
    CNameTrieNode* current = &root;
    for (std::string::const_iterator itname = name.begin(); itname + 1 != name.end(); ++itname)
    {
        nodeNameMapType::iterator itchild = current->children.find(*itname);
        if (itchild == current->children.end())
            return false;
        current = itchild->second;
    }
    current->children[name[name.size()-1]] = node;
    return true;
}

bool CNameTrie::ReadFromDisk(bool check)
{
    if (!db.Read(HASH_BLOCK, hashBlock))
        LogPrintf("%s: Couldn't read the best block's hash\n", __func__);
    if (!db.Read(CURRENT_HEIGHT, nCurrentHeight))
        LogPrintf("%s: Couldn't read the current height\n", __func__);
    boost::scoped_ptr<CDBIterator> pcursor(const_cast<CDBWrapper*>(&db)->NewIterator());
    pcursor->SeekToFirst();
    
    while (pcursor->Valid())
    {
        std::pair<char, std::string> key;
        if (pcursor->GetKey(key))
        {
            if (key.first == TRIE_NODE)
            {
                CNameTrieNode* node = new CNameTrieNode();
                if (pcursor->GetValue(*node))
                {
                    if (!InsertFromDisk(key.second, node))
                    {
                        return error("%s(): error restoring claim trie from disk", __func__);
                    }
                }
                else
                {
                    return error("%s(): error reading claim trie from disk", __func__);
                }
            }
        }
        pcursor->Next();
    }
    if (check)
    {
        LogPrintf("Checking Claim trie consistency...");
        if (checkConsistency())
        {
            LogPrintf("consistent\n");
            return true;
        }
        LogPrintf("inconsistent!\n");
        return false;
    }
    return true;
}

bool CNameTrieCache::recursiveComputeMerkleHash(CNameTrieNode* tnCurrent, std::string sPos) const
{
    if (sPos == "" && tnCurrent->empty())
    {
        cacheHashes[""] = uint256S("0000000000000000000000000000000000000000000000000000000000000001");
        return true;
    }
    std::vector<unsigned char> vchToHash;
    NodenodeCacheType::iterator cachedNode;


    for (nodeNameMapType::iterator it = tnCurrent->children.begin(); it != tnCurrent->children.end(); ++it)
    {
        std::stringstream ss;
        ss << it->first;
        std::string sNextPos = sPos + ss.str();
        if (dirtyHashes.count(sNextPos) != 0)
        {
            // the child might be in the cache, so look for it there
            cachedNode = cache.find(sNextPos);
            if (cachedNode != cache.end())
                recursiveComputeMerkleHash(cachedNode->second, sNextPos);
            else
                recursiveComputeMerkleHash(it->second, sNextPos);
        }
        vchToHash.push_back(it->first);
        hashMapType::iterator ithash = cacheHashes.find(sNextPos);
        if (ithash != cacheHashes.end())
        {
            vchToHash.insert(vchToHash.end(), ithash->second.begin(), ithash->second.end());
        }
        else
        {
            vchToHash.insert(vchToHash.end(), it->second->hash.begin(), it->second->hash.end());
        }
    }
    
    CNameValue claim;
    bool hasClaim = tnCurrent->getBestClaim(claim);

    if (hasClaim)
    {
        int nHeightOfLastTakeover;
        if(!getLastTakeoverForName(sPos, nHeightOfLastTakeover))
	{
            LogPrintf("getLastTakeoverForName is error %d,%s\n",__LINE__,__func__);
		return false;
	}
        uint256 valueHash = namegetValueHash(claim.outPoint, nHeightOfLastTakeover);
        vchToHash.insert(vchToHash.end(), valueHash.begin(), valueHash.end());
    }

    CHash256 hasher;
    std::vector<unsigned char> vchHash(hasher.OUTPUT_SIZE);
    hasher.Write(vchToHash.data(), vchToHash.size());
    hasher.Finalize(&(vchHash[0]));
    cacheHashes[sPos] = uint256(vchHash);
    std::set<std::string>::iterator itDirty = dirtyHashes.find(sPos);
    if (itDirty != dirtyHashes.end())
        dirtyHashes.erase(itDirty);
    return true;
}

uint256 CNameTrieCache::getMerkleHash() const
{
    if (empty())
    {
        uint256 one(uint256S("0000000000000000000000000000000000000000000000000000000000000001"));
        return one;
    }
    if (dirty())
    {
        NodenodeCacheType::iterator cachedNode = cache.find("");
        if (cachedNode != cache.end())
            recursiveComputeMerkleHash(cachedNode->second, "");
        else
            recursiveComputeMerkleHash(&(base->root), "");
    }
    hashMapType::iterator ithash = cacheHashes.find("");
    if (ithash != cacheHashes.end())
        return ithash->second;
    else
        return base->root.hash;
}

bool CNameTrieCache::empty() const
{
    return base->empty() && cache.empty();
}

CNameTrieNode* CNameTrieCache::addNodeToCache(const std::string& position, CNameTrieNode* original) const
{
    if (!original)
        original = new CNameTrieNode();
    CNameTrieNode* cacheCopy = new CNameTrieNode(*original);
    cache[position] = cacheCopy;
    NodenodeCacheType::const_iterator itOriginals = block_originals.find(position);
    if (block_originals.end() == itOriginals)
    {
        CNameTrieNode* originalCopy = new CNameTrieNode(*original);
        block_originals[position] = originalCopy;
    }
    return cacheCopy;
}

bool CNameTrieCache::getOriginalInfoForName(const std::string& name, CNameValue& claim) const
{
    NodenodeCacheType::const_iterator itOriginalCache = block_originals.find(name);
    if (itOriginalCache == block_originals.end())
    {
        return base->getInfoForName(name, claim);
    }
    return itOriginalCache->second->getBestClaim(claim);
}

bool CNameTrieCache::insertClaimIntoTrie(const std::string& name, CNameValue claim, bool fCheckTakeover) const
{
    if(!base)
    {
        LogPrintf("base is error %d,%s\n",__LINE__,__func__);
	    return false;
    }
    CNameTrieNode* currentNode = &(base->root);
    NodenodeCacheType::iterator cachedNode;
    cachedNode = cache.find("");
    if (cachedNode != cache.end())
        currentNode = cachedNode->second;
    for (std::string::const_iterator itCur = name.begin(); itCur != name.end(); ++itCur)
    {
        std::string sCurrentSubstring(name.begin(), itCur);
        std::string sNextSubstring(name.begin(), itCur + 1);

        cachedNode = cache.find(sNextSubstring);
        if (cachedNode != cache.end())
        {
            currentNode = cachedNode->second;
            continue;
        }
        nodeNameMapType::iterator childNode = currentNode->children.find(*itCur);
        if (childNode != currentNode->children.end())
        {
            currentNode = childNode->second;
            continue;
        }
        
        // This next substring doesn't exist in the cache and the next
        // character doesn't exist in current node's children, so check
        // if the current node is in the cache, and if it's not, copy
        // it and stick it in the cache, and then create a new node as
        // its child and stick that in the cache. We have to have both
        // this node and its child in the cache so that the current
        // node's child map will contain the next letter, which will be
        // used to find the child in the cache. This is necessary in
        // order to calculate the merkle hash.
        cachedNode = cache.find(sCurrentSubstring);
        if (cachedNode != cache.end())
        {
            if(cachedNode->second != currentNode)
	    {
                LogPrintf("cachedNode->second != currentNode is error %d,%s\n",__LINE__,__func__);
		    return false;
	    }
        }
        else
        {
            currentNode = addNodeToCache(sCurrentSubstring, currentNode);
        }
        CNameTrieNode* newNode = addNodeToCache(sNextSubstring, NULL);
        currentNode->children[*itCur] = newNode;
        currentNode = newNode;
    }

    cachedNode = cache.find(name);
    if (cachedNode != cache.end())
    {
        if(cachedNode->second != currentNode)
	{
            LogPrintf("cachedNode->second != currentNode is error %d,%s\n",__LINE__,__func__);
		return false;
	}
    }
    else
    {
        currentNode = addNodeToCache(name, currentNode);
    }
    bool fChanged = false;
    if (currentNode->claims.empty())
    {
        fChanged = true;
        currentNode->insertClaim(claim);
    }
    else
    {
        CNameValue currentTop = currentNode->claims.front();
        currentNode->insertClaim(claim);
        supportNameMapEntryType node;
        getSupportsForName(name, node);
        currentNode->reorderClaims(node);
        if (currentTop != currentNode->claims.front())
            fChanged = true;
    }
    if (fChanged)
    {
        for (std::string::const_iterator itCur = name.begin(); itCur != name.end(); ++itCur)
        {
            std::string sub(name.begin(), itCur);
            dirtyHashes.insert(sub);
        }
        dirtyHashes.insert(name);
        if (fCheckTakeover)
            namesToCheckForTakeover.insert(name);
    }
    return true;
}

bool CNameTrieCache::removeClaimFromTrie(const std::string& name, const COutPoint& outPoint, CNameValue& claim, bool fCheckTakeover) const
{
    if(!base)
    {
        LogPrintf("base is error %d,%s\n",__LINE__,__func__);
	    return false;
    }
    CNameTrieNode* currentNode = &(base->root);
    NodenodeCacheType::iterator cachedNode;
    cachedNode = cache.find("");
    if (cachedNode != cache.end())
        currentNode = cachedNode->second;
    if(currentNode == NULL) // If there is no root in either the trie or the cache, how can there be any names to remove?
    {
	    LogPrintf("currentNode is error %d,%s\n",__LINE__,__func__);
	    return false;
    }
    for (std::string::const_iterator itCur = name.begin(); itCur != name.end(); ++itCur)
    {
        std::string sCurrentSubstring(name.begin(), itCur);
        std::string sNextSubstring(name.begin(), itCur + 1);

        cachedNode = cache.find(sNextSubstring);
        if (cachedNode != cache.end())
        {
            currentNode = cachedNode->second;
            continue;
        }
        nodeNameMapType::iterator childNode = currentNode->children.find(*itCur);
        if (childNode != currentNode->children.end())
        {
            currentNode = childNode->second;
            continue;
        }
        LogPrintf("%s: The name %s does not exist in the trie\n", __func__, name.c_str());
        return false;
    }

    cachedNode = cache.find(name);
    if (cachedNode != cache.end())
    {
        if(cachedNode->second != currentNode)
	{
            LogPrintf("cachedNode->second != currentNode is error %d,%s\n",__LINE__,__func__);
		return false;
	}
    }
    else
    {
        currentNode = addNodeToCache(name, currentNode);
    }
    bool fChanged = false;
    if(currentNode == NULL)
    {
        LogPrintf("currentNode is error %d,%s\n",__LINE__,__func__);
	    return false;
    }
    bool success = false;
    
    if (currentNode->claims.empty())
    {
        LogPrintf("%s: Asked to remove claim from node without claims\n", __func__);
        return false;
    }
    CNameValue currentTop = currentNode->claims.front();

    success = currentNode->removeClaim(outPoint, claim);
    
    if (!currentNode->claims.empty())
    {
        supportNameMapEntryType node;
        getSupportsForName(name, node);
        currentNode->reorderClaims(node);
        if (currentTop != currentNode->claims.front())
            fChanged = true;
    }
    else
        fChanged = true;
    
    if (!success)
    {
        LogPrintf("%s: Removing a claim was unsuccessful. name = %s, txhash = %s, nOut = %d", __func__, name.c_str(), outPoint.hash.GetHex(), outPoint.n);
        return false;
    }

    if (fChanged)
    {
        for (std::string::const_iterator itCur = name.begin(); itCur != name.end(); ++itCur)
        {
            std::string sub(name.begin(), itCur);
            dirtyHashes.insert(sub);
        }
        dirtyHashes.insert(name);
        if (fCheckTakeover)
            namesToCheckForTakeover.insert(name);
    }
    CNameTrieNode* rootNode = &(base->root);
    cachedNode = cache.find("");
    if (cachedNode != cache.end())
        rootNode = cachedNode->second;
    return recursivePruneName(rootNode, 0, name);
}

bool CNameTrieCache::recursivePruneName(CNameTrieNode* tnCurrent, unsigned int nPos, std::string sName, bool* pfNullified) const
{
    bool fNullified = false;
    std::string sCurrentSubstring = sName.substr(0, nPos);
    if (nPos < sName.size())
    {
        std::string sNextSubstring = sName.substr(0, nPos + 1);
        unsigned char cNext = sName.at(nPos);
        CNameTrieNode* tnNext = NULL;
        NodenodeCacheType::iterator cachedNode = cache.find(sNextSubstring);
        if (cachedNode != cache.end())
            tnNext = cachedNode->second;
        else
        {
            nodeNameMapType::iterator childNode = tnCurrent->children.find(cNext);
            if (childNode != tnCurrent->children.end())
                tnNext = childNode->second;
        }
        if (tnNext == NULL)
            return false;
        bool fChildNullified = false;
        if (!recursivePruneName(tnNext, nPos + 1, sName, &fChildNullified))
            return false;
        if (fChildNullified)
        {
            // If the child nullified itself, the child should already be
            // out of the cache, and the character must now be removed
            // from the current node's map of child nodes to ensure that
            // it isn't found when calculating the merkle hash. But
            // tnCurrent isn't necessarily in the cache. If it's not, it
            // has to be added to the cache, so nothing is changed in the
            // trie. If the current node is added to the cache, however,
            // that does not imply that the parent node must be altered to 
            // reflect that its child is now in the cache, since it
            // already has a character in its child map which will be used
            // when calculating the merkle root.

            // First, find out if this node is in the cache.
            cachedNode = cache.find(sCurrentSubstring);
            if (cachedNode == cache.end())
            {
                // it isn't, so make a copy, stick it in the cache,
                // and make it the new current node
                tnCurrent = addNodeToCache(sCurrentSubstring, tnCurrent);
            }
            // erase the character from the current node, which is
            // now guaranteed to be in the cache
            nodeNameMapType::iterator childNode = tnCurrent->children.find(cNext);
            if (childNode != tnCurrent->children.end())
                tnCurrent->children.erase(childNode);
            else
                return false;
        }
    }
    if (sCurrentSubstring.size() != 0 && tnCurrent->empty())
    {
        // If the current node is in the cache, remove it from there
        NodenodeCacheType::iterator cachedNode = cache.find(sCurrentSubstring);
        if (cachedNode != cache.end())
        {
            if(tnCurrent != cachedNode->second)
	    {
                LogPrintf("cachedNode->second != currentNode is error %d,%s\n",__LINE__,__func__);
		    return false;
	    }
            delete tnCurrent;
            cache.erase(cachedNode);
        }
        fNullified = true;
    }
    if (pfNullified)
        *pfNullified = fNullified;
    return true;
}

nameQueueType::iterator CNameTrieCache::getQueueCacheRow(int nHeight, bool createIfNotExists) const
{
    nameQueueType::iterator itQueueRow = claimQueueCache.find(nHeight);
    if (itQueueRow == claimQueueCache.end())
    {
        // Have to make a new row it put in the cache, if createIfNotExists is true
        NameQueueRowType queueRow;
        // If the row exists in the base, copy its claims into the new row.
        bool exists = base->getQueueRow(nHeight, queueRow);
        if (!exists)
            if (!createIfNotExists)
                return itQueueRow;
        // Stick the new row in the cache
        std::pair<nameQueueType::iterator, bool> ret;
        ret = claimQueueCache.insert(std::pair<int, NameQueueRowType >(nHeight, queueRow));
        if(!ret.second)
	{
            LogPrintf("ret.second is error %d,%s\n",__LINE__,__func__);
	}
         
        itQueueRow = ret.first;
    }
    return itQueueRow;
}

NamequeueNameType::iterator CNameTrieCache::getQueueCacheNameRow(const std::string& name, bool createIfNotExists) const
{
    NamequeueNameType::iterator itQueueNameRow = claimQueueNameCache.find(name);
    if (itQueueNameRow == claimQueueNameCache.end())
    {
        // Have to make a new name row and put it in the cache, if createIfNotExists is true
        NamequeueNameRowType queueNameRow;
        // If the row exists in the base, copy its claims into the new row.
        bool exists = base->getQueueNameRow(name, queueNameRow);
        if (!exists)
            if (!createIfNotExists)
                return itQueueNameRow;
        // Stick the new row in the cache
        std::pair<NamequeueNameType::iterator, bool> ret;
        ret = claimQueueNameCache.insert(std::pair<std::string, NamequeueNameRowType>(name, queueNameRow));
        if(!ret.second)
	{
            LogPrintf("ret.second is error %d,%s\n",__LINE__,__func__);
	}
        itQueueNameRow = ret.first;
    }
    return itQueueNameRow;
}

bool CNameTrieCache::addClaim(const std::string& name, const COutPoint& outPoint, uint160 claimId, CAmount nAmount, int nHeight,std::string addr) const
{
    LogPrintf("%s: name: %s, txhash: %s, nOut: %d, claimId: %s, nAmount: %d, nHeight: %d, nCurrentHeight: %d\n", __func__, name, outPoint.hash.GetHex(), outPoint.n, claimId.GetHex(), nAmount, nHeight, nCurrentHeight);
    //assert(nHeight == nCurrentHeight + 1);
    //if(nHeight != nCurrentHeight )
    //{
    //     LogPrintf("nHeight != nCurrentHeight is error %d,%s\n",__LINE__,__func__);
	//    return false;
    //}
    CNameValue currentClaim;
    int delayForClaim;
    if (getOriginalInfoForName(name, currentClaim) && currentClaim.claimId == claimId)
    {
        LogPrintf("%s: This is an update to a best claim.\n", __func__);
        delayForClaim = 0;
    }
    else
    {
        delayForClaim = getDelayForName(name);
    }
    CNameValue newClaim(outPoint, claimId, nAmount, nHeight, nHeight + delayForClaim,addr,name);
    return addClaimToQueues(name, newClaim);
}

bool CNameTrieCache::undoSpendClaim(const std::string& name, const COutPoint& outPoint, uint160 claimId, CAmount nAmount, int nHeight, int nValidAtHeight,std::string addr) const
{
    LogPrintf("%s: name: %s, txhash: %s, nOut: %d, claimId: %s, nAmount: %d, nHeight: %d, nValidAtHeight: %d, nCurrentHeight: %d\n", __func__, name, outPoint.hash.GetHex(), outPoint.n, claimId.GetHex(), nAmount, nHeight, nValidAtHeight, nCurrentHeight);
    CNameValue claim(outPoint, claimId, nAmount, nHeight, nValidAtHeight,addr,name);
    if (nValidAtHeight < nCurrentHeight)
    {
        NameOutPointType entry(name, claim.outPoint);
        addToExpirationQueue(claim.nHeight + base->nExpirationTime, entry);
        return insertClaimIntoTrie(name, claim, false);
    }
    else
    {
        return addClaimToQueues(name, claim);
    }
}

bool CNameTrieCache::addClaimToQueues(const std::string& name, CNameValue& claim) const
{
    LogPrintf("%s: nValidAtHeight: %d\n", __func__, claim.nValidAtHeight);
    NameQueueEntryType entry(name, claim);
    nameQueueType::iterator itQueueRow = getQueueCacheRow(claim.nValidAtHeight, true);
    NamequeueNameType::iterator itQueueNameRow = getQueueCacheNameRow(name, true);
    itQueueRow->second.push_back(entry);
    itQueueNameRow->second.push_back(NameoutPointHeightType(claim.outPoint, claim.nValidAtHeight));
    NameOutPointType expireEntry(name, claim.outPoint);
    addToExpirationQueue(claim.nHeight + base->nExpirationTime, expireEntry);
    return true;
}

bool CNameTrieCache::removeClaimFromQueue(const std::string& name, const COutPoint& outPoint, CNameValue& claim) const
{
    NamequeueNameType::iterator itQueueNameRow = getQueueCacheNameRow(name, false);
    if (itQueueNameRow == claimQueueNameCache.end())
    {
        return false;
    }
    NamequeueNameRowType::iterator itQueueName;
    for (itQueueName = itQueueNameRow->second.begin(); itQueueName != itQueueNameRow->second.end(); ++itQueueName)
    {
        if (itQueueName->outPoint == outPoint)
        {
            break;
        }
    }
    if (itQueueName == itQueueNameRow->second.end())
    {
        return false;
    }
    nameQueueType::iterator itQueueRow = getQueueCacheRow(itQueueName->nHeight, false);
    if (itQueueRow != claimQueueCache.end())
    {
        NameQueueRowType::iterator itQueue;
        for (itQueue = itQueueRow->second.begin(); itQueue != itQueueRow->second.end(); ++itQueue)
        {
            if (name == itQueue->first && itQueue->second.outPoint == outPoint)
            {
                break;
            }
        }
        if (itQueue != itQueueRow->second.end())
        {
            std::swap(claim, itQueue->second);
            itQueueNameRow->second.erase(itQueueName);
            itQueueRow->second.erase(itQueue);
            return true;
        }
    }
    LogPrintf("%s: An inconsistency was found in the claim queue. Please report this to the developers:\nFound in named queue but not in height queue: name: %s, txid: %s, nOut: %d, nValidAtHeight: %d, current height: %d\n", __func__, name, outPoint.hash.GetHex(), outPoint.n, itQueueName->nHeight, nCurrentHeight);
    return false;
}

bool CNameTrieCache::undoAddClaim(const std::string& name, const COutPoint& outPoint, int nHeight) const
{
    int throwaway;
    return removeClaim(name, outPoint, nHeight, throwaway, false);
}

bool CNameTrieCache::spendClaim(const std::string& name, const COutPoint& outPoint, int nHeight, int& nValidAtHeight) const
{
    return removeClaim(name, outPoint, nHeight, nValidAtHeight, true);
}

bool CNameTrieCache::removeClaim(const std::string& name, const COutPoint& outPoint, int nHeight, int& nValidAtHeight, bool fCheckTakeover) const
{
    LogPrintf("%s: name: %s, txhash: %s, nOut: %s, nHeight: %s, nCurrentHeight: %s\n", __func__, name, outPoint.hash.GetHex(), outPoint.n, nHeight, nCurrentHeight);
    bool removed = false;
    CNameValue claim;
    if (removeClaimFromQueue(name, outPoint, claim))
    {
        removed = true;
    }
    if (removed == false && removeClaimFromTrie(name, outPoint, claim, fCheckTakeover))
    {
        removed = true;
    }
    if (removed == true)
    {
        nValidAtHeight = claim.nValidAtHeight;
        removeFromExpirationQueue(name, outPoint, nHeight);
    }
    return removed;
}

void CNameTrieCache::addToExpirationQueue(int nExpirationHeight, NameOutPointType& entry) const
{
    expirationNameQueueType::iterator itQueueRow = getExpirationQueueCacheRow(nExpirationHeight, true);
    itQueueRow->second.push_back(entry);
}

void CNameTrieCache::removeFromExpirationQueue(const std::string& name, const COutPoint& outPoint, int nHeight) const
{
    int expirationHeight = nHeight + base->nExpirationTime;
    expirationNameQueueType::iterator itQueueRow = getExpirationQueueCacheRow(expirationHeight, false);
    expirationNameQueueRowType::iterator itQueue;
    if (itQueueRow != expirationQueueCache.end())
    {
        for (itQueue = itQueueRow->second.begin(); itQueue != itQueueRow->second.end(); ++itQueue)
        {
            if (name == itQueue->name && outPoint == itQueue->outPoint)
                break;
        }
    }
    if (itQueue != itQueueRow->second.end())
    {
        itQueueRow->second.erase(itQueue);
    }
}

expirationNameQueueType::iterator CNameTrieCache::getExpirationQueueCacheRow(int nHeight, bool createIfNotExists) const
{
    expirationNameQueueType::iterator itQueueRow = expirationQueueCache.find(nHeight);
    if (itQueueRow == expirationQueueCache.end())
    {
        // Have to make a new row it put in the cache, if createIfNotExists is true
        expirationNameQueueRowType queueRow;
        // If the row exists in the base, copy its claims into the new row.
        bool exists = base->getExpirationQueueRow(nHeight, queueRow);
        if (!exists)
            if (!createIfNotExists)
                return itQueueRow;
        // Stick the new row in the cache
        std::pair<expirationNameQueueType::iterator, bool> ret;
        ret = expirationQueueCache.insert(std::pair<int, expirationNameQueueRowType >(nHeight, queueRow));
        if(!ret.second)
	{
            LogPrintf("ret.second is error %d,%s\n",__LINE__,__func__);
	}
        itQueueRow = ret.first;
    }
    return itQueueRow;
}

bool CNameTrieCache::reorderTrieNode(const std::string& name, bool fCheckTakeover) const
{
    if(!base)
    {
        LogPrintf("base is NULL %d,%s\n",__LINE__,__func__);
	    return false;
    }
    NodenodeCacheType::iterator cachedNode;
    cachedNode = cache.find(name);
    if (cachedNode == cache.end())
    {
        CNameTrieNode* currentNode = &(base->root);
        for (std::string::const_iterator itCur = name.begin(); itCur != name.end(); ++itCur)
        {
            std::string sCurrentSubstring(name.begin(), itCur);
            std::string sNextSubstring(name.begin(), itCur + 1);

            cachedNode = cache.find(sNextSubstring);
            if (cachedNode != cache.end())
            {
                currentNode = cachedNode->second;
                continue;
            }
            nodeNameMapType::iterator childNode = currentNode->children.find(*itCur);
            if (childNode != currentNode->children.end())
            {
                currentNode = childNode->second;
                continue;
            }
            // The node doesn't exist, so it can't be reordered.
            return true;
        }
        currentNode = new CNameTrieNode(*currentNode);
        std::pair<NodenodeCacheType::iterator, bool> ret;
        ret = cache.insert(std::pair<std::string, CNameTrieNode*>(name, currentNode));
        if(!ret.second)
	{
            LogPrintf("ret.second is false %d,%s\n",__LINE__,__func__);
		return false;
	}
        cachedNode = ret.first;
    }
    bool fChanged = false;
    if (cachedNode->second->claims.empty())
    {
        // Nothing in there to reorder
        return true;
    }
    else
    {
        CNameValue currentTop = cachedNode->second->claims.front();
        supportNameMapEntryType node;
        getSupportsForName(name, node);
        cachedNode->second->reorderClaims(node);
        if (cachedNode->second->claims.front() != currentTop)
            fChanged = true;
    }
    if (fChanged)
    {
        for (std::string::const_iterator itCur = name.begin(); itCur != name.end(); ++itCur)
        {
            std::string sub(name.begin(), itCur);
            dirtyHashes.insert(sub);
        }
        dirtyHashes.insert(name);
        if (fCheckTakeover)
            namesToCheckForTakeover.insert(name);
    }
    return true;
}

bool CNameTrieCache::getSupportsForName(const std::string& name, supportNameMapEntryType& node) const
{
    NamesupportMapType::iterator cachedNode;
    cachedNode = supportCache.find(name);
    if (cachedNode != supportCache.end())
    {
        node = cachedNode->second;
        return true;
    }
    else
    {
        return base->getSupportNode(name, node);
    }
}

bool CNameTrieCache::insertSupportIntoMap(const std::string& name, CSupportNameValue support, bool fCheckTakeover) const
{
    NamesupportMapType::iterator cachedNode;
    // If this node is already in the cache, use that
    cachedNode = supportCache.find(name);
    // If not, copy the one from base if it exists, and use that
    if (cachedNode == supportCache.end())
    {
        supportNameMapEntryType node;
        base->getSupportNode(name, node);
        std::pair<NamesupportMapType::iterator, bool> ret;
        ret = supportCache.insert(std::pair<std::string, supportNameMapEntryType>(name, node));
        if(!ret.second)
	{
            LogPrintf("ret.second is error %d,%s\n",__LINE__,__func__);
		return false;
	}
        cachedNode = ret.first;
    }
    cachedNode->second.push_back(support);
    // See if this changed the biggest bid
    return reorderTrieNode(name,  fCheckTakeover);
}

bool CNameTrieCache::removeSupportFromMap(const std::string& name, const COutPoint& outPoint, CSupportNameValue& support, bool fCheckTakeover) const
{
    NamesupportMapType::iterator cachedNode;
    cachedNode = supportCache.find(name);
    if (cachedNode == supportCache.end())
    {
        supportNameMapEntryType node;
        if (!base->getSupportNode(name, node))
        {
            // clearly, this support does not exist
            return false;
        }
        std::pair<NamesupportMapType::iterator, bool> ret;
        ret = supportCache.insert(std::pair<std::string, supportNameMapEntryType>(name, node));
        if(!ret.second)
	{
            LogPrintf("ret.second is error %d,%s\n",__LINE__,__func__);
		return false;
	}
        cachedNode = ret.first;
    }
    supportNameMapEntryType::iterator itSupport;
    for (itSupport = cachedNode->second.begin(); itSupport != cachedNode->second.end(); ++itSupport)
    {
        if (itSupport->outPoint == outPoint)
        {
            break;
        }
    }
    if (itSupport != cachedNode->second.end())
    {
        std::swap(support, *itSupport);
        cachedNode->second.erase(itSupport);
        return reorderTrieNode(name, fCheckTakeover);
    }
    else
    {
        LogPrintf("CNameTrieCache::%s() : asked to remove a support that doesn't exist\n", __func__);
        return false;
    }
}

supportNameQueueType::iterator CNameTrieCache::getSupportQueueCacheRow(int nHeight, bool createIfNotExists) const
{
    supportNameQueueType::iterator itQueueRow = supportQueueCache.find(nHeight);
    if (itQueueRow == supportQueueCache.end())
    {
        NamesupportQueueRowType queueRow;
        bool exists = base->getSupportQueueRow(nHeight, queueRow);
        if (!exists)
            if (!createIfNotExists)
                return itQueueRow;
        // Stick the new row in the cache
        std::pair<supportNameQueueType::iterator, bool> ret;
        ret = supportQueueCache.insert(std::pair<int, NamesupportQueueRowType >(nHeight, queueRow));
        if(!ret.second)
	{
            LogPrintf("ret.second is error %d,%s\n",__LINE__,__func__);
	}
        itQueueRow = ret.first;
    }
    return itQueueRow;
}

NamequeueNameType::iterator CNameTrieCache::getSupportQueueCacheNameRow(const std::string& name, bool createIfNotExists) const
{
    NamequeueNameType::iterator itQueueNameRow = supportQueueNameCache.find(name);
    if (itQueueNameRow == supportQueueNameCache.end())
    {
        NamequeueNameRowType queueNameRow;
        bool exists = base->getSupportQueueNameRow(name, queueNameRow);
        if (!exists)
            if (!createIfNotExists)
                return itQueueNameRow;
        // Stick the new row in the name cache
        std::pair<NamequeueNameType::iterator, bool> ret;
        ret = supportQueueNameCache.insert(std::pair<std::string, NamequeueNameRowType>(name, queueNameRow));
        if(!ret.second)
	{
            LogPrintf("ret.second is error %d,%s\n",__LINE__,__func__);
	}
        itQueueNameRow = ret.first;
    }
    return itQueueNameRow;
}

bool CNameTrieCache::addSupportToQueues(const std::string& name, CSupportNameValue& support) const
{
    LogPrintf("%s: nValidAtHeight: %d\n", __func__, support.nValidAtHeight);
    NamesupportQueueEntryType entry(name, support);
    supportNameQueueType::iterator itQueueRow = getSupportQueueCacheRow(support.nValidAtHeight, true);
    NamequeueNameType::iterator itQueueNameRow = getSupportQueueCacheNameRow(name, true);
    itQueueRow->second.push_back(entry);
    itQueueNameRow->second.push_back(NameoutPointHeightType(support.outPoint, support.nValidAtHeight));
    NameOutPointType expireEntry(name, support.outPoint);
    addSupportToExpirationQueue(support.nHeight + base->nExpirationTime, expireEntry);
    return true;
}

bool CNameTrieCache::removeSupportFromQueue(const std::string& name, const COutPoint& outPoint, CSupportNameValue& support) const
{
    NamequeueNameType::iterator itQueueNameRow = getSupportQueueCacheNameRow(name, false);
    if (itQueueNameRow == supportQueueNameCache.end())
    {
        return false;
    }
    NamequeueNameRowType::iterator itQueueName;
    for (itQueueName = itQueueNameRow->second.begin(); itQueueName != itQueueNameRow->second.end(); ++itQueueName)
    {
        if (itQueueName->outPoint == outPoint)
        {
            break;
        }
    }
    if (itQueueName == itQueueNameRow->second.end())
    {
        return false;
    }
    supportNameQueueType::iterator itQueueRow = getSupportQueueCacheRow(itQueueName->nHeight, false);
    if (itQueueRow != supportQueueCache.end())
    {
        NamesupportQueueRowType::iterator itQueue;
        for (itQueue = itQueueRow->second.begin(); itQueue != itQueueRow->second.end(); ++itQueue)
        {
            CSupportNameValue& support = itQueue->second;
            if (name == itQueue->first && support.outPoint == outPoint)
            {
                break;
            }
        }
        if (itQueue != itQueueRow->second.end())
        {
            std::swap(support, itQueue->second);
            itQueueNameRow->second.erase(itQueueName);
            itQueueRow->second.erase(itQueue);
            return true;
        }
    }
    LogPrintf("%s: An inconsistency was found in the claim queue. Please report this to the developers:\nFound in named support queue but not in height support queue: name: %s, txid: %s, nOut: %d, nValidAtHeight: %d, current height: %d\n", __func__, name, outPoint.hash.GetHex(), outPoint.n, itQueueName->nHeight, nCurrentHeight);
    return false;
}

bool CNameTrieCache::addSupport(const std::string& name, const COutPoint& outPoint, CAmount nAmount, uint160 supportedClaimId, int nHeight) const
{
    LogPrintf("%s: name: %s, txhash: %s, nOut: %d, nAmount: %d, supportedClaimId: %s, nHeight: %d, nCurrentHeight: %d\n", __func__, name, outPoint.hash.GetHex(), outPoint.n, nAmount, supportedClaimId.GetHex(), nHeight, nCurrentHeight);
    //assert(nHeight == nCurrentHeight + 1);
    //if(nHeight != nCurrentHeight)
    //{
     //   LogPrintf("nHeight != nCurrentHeight is error %d,%s\n",__LINE__,__func__);
	//    return false;
   // }
    CNameValue claim;
    int delayForSupport;
    if (getOriginalInfoForName(name, claim) && claim.claimId == supportedClaimId)
    {
        LogPrintf("%s: This is a support to a best claim.\n", __func__);
        delayForSupport = 0;
    }
    else
    {
        delayForSupport = getDelayForName(name);
    }
    CSupportNameValue support(outPoint, supportedClaimId, nAmount, nHeight, nHeight + delayForSupport);
    return addSupportToQueues(name, support);
}

bool CNameTrieCache::undoSpendSupport(const std::string& name, const COutPoint& outPoint, uint160 supportedClaimId, CAmount nAmount, int nHeight, int nValidAtHeight) const
{
    LogPrintf("%s: name: %s, txhash: %s, nOut: %d, nAmount: %d, supportedClaimId: %s, nHeight: %d, nCurrentHeight: %d\n", __func__, name, outPoint.hash.GetHex(), outPoint.n, nAmount, supportedClaimId.GetHex(), nHeight, nCurrentHeight);
    CSupportNameValue support(outPoint, supportedClaimId, nAmount, nHeight, nValidAtHeight);
    if (nValidAtHeight < nCurrentHeight)
    {
        NameOutPointType entry(name, support.outPoint);
        addSupportToExpirationQueue(support.nHeight + base->nExpirationTime, entry);
        return insertSupportIntoMap(name, support, false);
    }
    else
    {
        return addSupportToQueues(name, support);
    }
}

bool CNameTrieCache::removeSupport(const std::string& name, const COutPoint& outPoint, int nHeight, int& nValidAtHeight, bool fCheckTakeover) const
{
    bool removed = false;
    CSupportNameValue support;
    if (removeSupportFromQueue(name, outPoint, support))
        removed = true;
    if (removed == false && removeSupportFromMap(name, outPoint, support, fCheckTakeover))
        removed = true;
    if (removed)
    {
        removeSupportFromExpirationQueue(name, outPoint, nHeight);
        nValidAtHeight = support.nValidAtHeight;
    }
    return removed;
}

void CNameTrieCache::addSupportToExpirationQueue(int nExpirationHeight, NameOutPointType& entry) const
{
    expirationNameQueueType::iterator itQueueRow = getSupportExpirationQueueCacheRow(nExpirationHeight, true);
    itQueueRow->second.push_back(entry);
}

void CNameTrieCache::removeSupportFromExpirationQueue(const std::string& name, const COutPoint& outPoint, int nHeight) const
{
    int expirationHeight = nHeight + base->nExpirationTime;
    expirationNameQueueType::iterator itQueueRow = getSupportExpirationQueueCacheRow(expirationHeight, false);
    expirationNameQueueRowType::iterator itQueue;
    if (itQueueRow != supportExpirationQueueCache.end())
    {
        for (itQueue = itQueueRow->second.begin(); itQueue != itQueueRow->second.end(); ++itQueue)
        {
            if (name == itQueue->name && outPoint == itQueue->outPoint)
                break;
        }
    }
    if (itQueue != itQueueRow->second.end())
    {
        itQueueRow->second.erase(itQueue);
    }
}

expirationNameQueueType::iterator CNameTrieCache::getSupportExpirationQueueCacheRow(int nHeight, bool createIfNotExists) const
{
    expirationNameQueueType::iterator itQueueRow = supportExpirationQueueCache.find(nHeight);
    if (itQueueRow == supportExpirationQueueCache.end())
    {
        // Have to make a new row it put in the cache, if createIfNotExists is true
        expirationNameQueueRowType queueRow;
        // If the row exists in the base, copy its claims into the new row.
        bool exists = base->getSupportExpirationQueueRow(nHeight, queueRow);
        if (!exists)
            if (!createIfNotExists)
                return itQueueRow;
        // Stick the new row in the cache
        std::pair<expirationNameQueueType::iterator, bool> ret;
        ret = supportExpirationQueueCache.insert(std::pair<int, expirationNameQueueRowType >(nHeight, queueRow));
        if(!ret.second)
	{
            LogPrintf("ret.second is error %d,%s\n",__LINE__,__func__);
	}
        itQueueRow = ret.first;
    }
    return itQueueRow;
}

bool CNameTrieCache::undoAddSupport(const std::string& name, const COutPoint& outPoint, int nHeight) const
{
    LogPrintf("%s: name: %s, txhash: %s, nOut: %d, nHeight: %d, nCurrentHeight: %d\n", __func__, name, outPoint.hash.GetHex(), outPoint.n, nHeight, nCurrentHeight);
    int throwaway;
    return removeSupport(name, outPoint, nHeight, throwaway, false);
}

bool CNameTrieCache::spendSupport(const std::string& name, const COutPoint& outPoint, int nHeight, int& nValidAtHeight) const
{
    LogPrintf("%s: name: %s, txhash: %s, nOut: %d, nHeight: %d, nCurrentHeight: %d\n", __func__, name, outPoint.hash.GetHex(), outPoint.n, nHeight, nCurrentHeight);
    return removeSupport(name, outPoint, nHeight, nValidAtHeight, true);
}

bool CNameTrieCache::incrementBlock(insertNameUndoType& insertUndo, NameQueueRowType& expireUndo, insertNameUndoType& insertSupportUndo, NamesupportQueueRowType& expireSupportUndo, std::vector<std::pair<std::string, int> >& takeoverHeightUndo) const
{
    LogPrintf("%s: nCurrentHeight (before increment): %d\n", __func__, nCurrentHeight);
    nameQueueType::iterator itQueueRow = getQueueCacheRow(nCurrentHeight, false);
    if (itQueueRow != claimQueueCache.end())
    {
        for (NameQueueRowType::iterator itEntry = itQueueRow->second.begin(); itEntry != itQueueRow->second.end(); ++itEntry)
        {
            bool found = false;
            NamequeueNameType::iterator itQueueNameRow = getQueueCacheNameRow(itEntry->first, false);
            if (itQueueNameRow != claimQueueNameCache.end())
            {
                for (NamequeueNameRowType::iterator itQueueName = itQueueNameRow->second.begin(); itQueueName != itQueueNameRow->second.end(); ++itQueueName)
                {
                    if (itQueueName->outPoint == itEntry->second.outPoint && itQueueName->nHeight == nCurrentHeight)
                    {
                        found = true;
                        itQueueNameRow->second.erase(itQueueName);
                        break;
                    }
                }
            }
            if (!found)
            {
                LogPrintf("%s: An inconsistency was found in the claim queue. Please report this to the developers:\nFound in height queue but not in named queue: name: %s, txid: %s, nOut: %d, nValidAtHeight: %d, current height: %d\n", __func__, itEntry->first, itEntry->second.outPoint.hash.GetHex(), itEntry->second.outPoint.n, itEntry->second.nValidAtHeight, nCurrentHeight);
                if (itQueueNameRow != claimQueueNameCache.end())
                {
                    LogPrintf("Claims found for that name:\n");
                    for (NamequeueNameRowType::iterator itQueueName = itQueueNameRow->second.begin(); itQueueName != itQueueNameRow->second.end(); ++itQueueName)
                    {
                        LogPrintf("\ttxid: %s, nOut: %d, nValidAtHeight: %d\n", itQueueName->outPoint.hash.GetHex(), itQueueName->outPoint.n, itQueueName->nHeight);
                    }
                }
                else
                {
                    LogPrintf("No claims found for that name\n");
                }
            }
            if(!found)
	    {
                LogPrintf("found is error %d,%s\n",__LINE__,__func__);
		    return false;
	    }
            insertClaimIntoTrie(itEntry->first, itEntry->second, true);
            insertUndo.push_back(NameOutPointHeightType(itEntry->first, itEntry->second.outPoint, itEntry->second.nValidAtHeight));
        }
        itQueueRow->second.clear();
    }
    expirationNameQueueType::iterator itExpirationRow = getExpirationQueueCacheRow(nCurrentHeight, false);
    if (itExpirationRow != expirationQueueCache.end())
    {
        for (expirationNameQueueRowType::iterator itEntry = itExpirationRow->second.begin(); itEntry != itExpirationRow->second.end(); ++itEntry)
        {
            CNameValue claim;
            if(!removeClaimFromTrie(itEntry->name, itEntry->outPoint, claim, true))
	    {
                LogPrintf("removeClaimFromTrie return is error false %d,%s\n",__LINE__,__func__);
		    return false;
	    }
            expireUndo.push_back(std::make_pair(itEntry->name, claim));
        }
        itExpirationRow->second.clear();
    }
    supportNameQueueType::iterator itSupportRow = getSupportQueueCacheRow(nCurrentHeight, false);
    if (itSupportRow != supportQueueCache.end())
    {
        for (NamesupportQueueRowType::iterator itSupport = itSupportRow->second.begin(); itSupport != itSupportRow->second.end(); ++itSupport)
        {
            bool found = false;
            NamequeueNameType::iterator itSupportNameRow = getSupportQueueCacheNameRow(itSupport->first, false);
            if (itSupportNameRow != supportQueueNameCache.end())
            {
                for (NamequeueNameRowType::iterator itSupportName = itSupportNameRow->second.begin(); itSupportName != itSupportNameRow->second.end(); ++itSupportName)
                {
                    if (itSupportName->outPoint == itSupport->second.outPoint && itSupportName->nHeight == itSupport->second.nValidAtHeight)
                    {
                        found = true;
                        itSupportNameRow->second.erase(itSupportName);
                        break;
                    }
                }
            }
            if (!found)
            {
                LogPrintf("%s: An inconsistency was found in the support queue. Please report this to the developers:\nFound in height queue but not in named queue: %s, txid: %s, nOut: %d, nValidAtHeight: %d, current height: %d\n", __func__, itSupport->first, itSupport->second.outPoint.hash.GetHex(), itSupport->second.outPoint.n, itSupport->second.nValidAtHeight, nCurrentHeight);
                if (itSupportNameRow != supportQueueNameCache.end())
                {
                    LogPrintf("Supports found for that name:\n");
                    for (NamequeueNameRowType::iterator itSupportName = itSupportNameRow->second.begin(); itSupportName != itSupportNameRow->second.end(); ++itSupportName)
                    {
                        LogPrintf("\ttxid: %s, nOut: %d, nValidAtHeight: %d\n", itSupportName->outPoint.hash.GetHex(), itSupportName->outPoint.n, itSupportName->nHeight);
                    }
                }
                else
                {
                    LogPrintf("No support found for that name\n");
                }
            }
            insertSupportIntoMap(itSupport->first, itSupport->second, true);
            insertSupportUndo.push_back(NameOutPointHeightType(itSupport->first, itSupport->second.outPoint, itSupport->second.nValidAtHeight));
        }
        itSupportRow->second.clear();
    }
    expirationNameQueueType::iterator itSupportExpirationRow = getSupportExpirationQueueCacheRow(nCurrentHeight, false);
    if (itSupportExpirationRow != supportExpirationQueueCache.end())
    {
        for (expirationNameQueueRowType::iterator itEntry = itSupportExpirationRow->second.begin(); itEntry != itSupportExpirationRow->second.end(); ++itEntry)
        {
            CSupportNameValue support;
            if(!removeSupportFromMap(itEntry->name, itEntry->outPoint, support, true))
	    {
                LogPrintf("removeSupportFromMap return error %d,%s\n",__LINE__,__func__);
		    return false;
	    }
		    
            expireSupportUndo.push_back(std::make_pair(itEntry->name, support));
        }
        itSupportExpirationRow->second.clear();
    }
    // check each potentially taken over name to see if a takeover occurred.
    // if it did, then check the claim and support insertion queues for 
    // the names that have been taken over, immediately insert all claim and
    // supports for those names, and stick them in the insertUndo or
    // insertSupportUndo vectors, with the nValidAtHeight they had prior to
    // this block.
    // Run through all names that have been taken over
    for (std::set<std::string>::iterator itNamesToCheck = namesToCheckForTakeover.begin(); itNamesToCheck != namesToCheckForTakeover.end(); ++itNamesToCheck)
    {
        // Check if a takeover has occurred
        NodenodeCacheType::iterator itCachedNode = cache.find(*itNamesToCheck);
        // many possibilities
        // if this node is new, don't put it into the undo -- there will be nothing to restore, after all
        // if all of this node's claims were deleted, it should be put into the undo -- there could be
        // claims in the queue for that name and the takeover height should be the current height
        // if the node is not in the cache, or getbestclaim fails, that means all of its claims were
        // deleted
        // if getOriginalInfoForName returns false, that means it's new and shouldn't go into the undo
        // if both exist, and the current best claim is not the same as or the parent to the new best
        // claim, then ownership has changed and the current height of last takeover should go into
        // the queue
        CNameValue claimInCache;
        CNameValue claimInTrie;
        bool haveClaimInCache;
        bool haveClaimInTrie;
        if (itCachedNode == cache.end())
        {
            haveClaimInCache = false;
        }
        else
        {
            haveClaimInCache = itCachedNode->second->getBestClaim(claimInCache);
        }
        haveClaimInTrie = getOriginalInfoForName(*itNamesToCheck, claimInTrie);
        bool takeoverHappened = false;
        if (!haveClaimInTrie)
        {
            takeoverHappened = true;
        }
        else if (!haveClaimInCache)
        {
            takeoverHappened = true;
        }
        else if (claimInCache != claimInTrie)
        {
            if (claimInCache.claimId != claimInTrie.claimId)
            {
                takeoverHappened = true;
            }
        }
        if (takeoverHappened)
        {
            // Get all claims in the queue for that name
            NamequeueNameType::iterator itQueueNameRow = getQueueCacheNameRow(*itNamesToCheck, false);
            if (itQueueNameRow != claimQueueNameCache.end())
            {
                for (NamequeueNameRowType::iterator itQueueName = itQueueNameRow->second.begin(); itQueueName != itQueueNameRow->second.end(); ++itQueueName)
                {
                    bool found = false;
                    // Pull those claims out of the height-based queue
                    nameQueueType::iterator itQueueRow = getQueueCacheRow(itQueueName->nHeight, false);
                    NameQueueRowType::iterator itQueue;
                    if (itQueueRow != claimQueueCache.end())
                    {
                        for (itQueue = itQueueRow->second.begin(); itQueue != itQueueRow->second.end(); ++itQueue)
                        {
                            if (*itNamesToCheck == itQueue->first && itQueue->second.outPoint == itQueueName->outPoint && itQueue->second.nValidAtHeight == itQueueName->nHeight)
                            {
                                found = true;
                                break;
                            }
                        }
                    }
                    if (found)
                    {
                        // Insert them into the queue undo with their previous nValidAtHeight
                        insertUndo.push_back(NameOutPointHeightType(itQueue->first, itQueue->second.outPoint, itQueue->second.nValidAtHeight));
                        // Insert them into the name trie with the new nValidAtHeight
                        itQueue->second.nValidAtHeight = nCurrentHeight;
                        insertClaimIntoTrie(itQueue->first, itQueue->second, false);
                        // Delete them from the height-based queue
                        itQueueRow->second.erase(itQueue);
                    }
                    else
                    {
                        LogPrintf("%s(): An inconsistency was found in the claim queue. Please report this to the developers:\nClaim found in name queue but not in height based queue:\nname: %s, txid: %s, nOut: %d, nValidAtHeight in name based queue: %d, current height: %d\n", __func__, *itNamesToCheck, itQueueName->outPoint.hash.GetHex(), itQueueName->outPoint.n, itQueueName->nHeight, nCurrentHeight);
                    }
                    if(!found)
		    {
                        LogPrintf("found return error %d,%s\n",__LINE__,__func__);
			    return false;
		    }
                }
                // remove all claims from the queue for that name
                itQueueNameRow->second.clear();
            }
            // 
            // Then, get all supports in the queue for that name
            NamequeueNameType::iterator itSupportQueueNameRow = getSupportQueueCacheNameRow(*itNamesToCheck, false);
            if (itSupportQueueNameRow != supportQueueNameCache.end())
            {
                for (NamequeueNameRowType::iterator itSupportQueueName = itSupportQueueNameRow->second.begin(); itSupportQueueName != itSupportQueueNameRow->second.end(); ++itSupportQueueName)
                {
                    // Pull those supports out of the height-based queue
                    supportNameQueueType::iterator itSupportQueueRow = getSupportQueueCacheRow(itSupportQueueName->nHeight, false);
                    if (itSupportQueueRow != supportQueueCache.end())
                    {
                        NamesupportQueueRowType::iterator itSupportQueue;
                        for (itSupportQueue = itSupportQueueRow->second.begin(); itSupportQueue != itSupportQueueRow->second.end(); ++itSupportQueue)
                        {
                            if (*itNamesToCheck == itSupportQueue->first && itSupportQueue->second.outPoint == itSupportQueueName->outPoint && itSupportQueue->second.nValidAtHeight == itSupportQueueName->nHeight)
                            {
                                break;
                            }
                        }
                        if (itSupportQueue != itSupportQueueRow->second.end())
                        {
                            // Insert them into the support queue undo with the previous nValidAtHeight
                            insertSupportUndo.push_back(NameOutPointHeightType(itSupportQueue->first, itSupportQueue->second.outPoint, itSupportQueue->second.nValidAtHeight));
                            // Insert them into the support map with the new nValidAtHeight
                            itSupportQueue->second.nValidAtHeight = nCurrentHeight;
                            insertSupportIntoMap(itSupportQueue->first, itSupportQueue->second, false);
                            // Delete them from the height-based queue
                            itSupportQueueRow->second.erase(itSupportQueue);
                        }
                        else
                        {
                            // here be problems TODO: show error, assert false
                        }
                    }
                    else
                    {
                        // here be problems
                    }
                }
                // remove all supports from the queue for that name
                itSupportQueueNameRow->second.clear();
            }
            
            // save the old last height so that it can be restored if the block is undone
            if (haveClaimInTrie)
            {
                int nHeightOfLastTakeover;
                if(!getLastTakeoverForName(*itNamesToCheck, nHeightOfLastTakeover))
		{
                    LogPrintf("getLastTakeoverForName return error %d,%s\n",__LINE__,__func__);
			return false;
		}
                takeoverHeightUndo.push_back(std::make_pair(*itNamesToCheck, nHeightOfLastTakeover));
            }
            itCachedNode = cache.find(*itNamesToCheck);
            if (itCachedNode != cache.end())
            {
                cacheTakeoverHeights[*itNamesToCheck] = nCurrentHeight;
            }
        }
    }
    for (NodenodeCacheType::const_iterator itOriginals = block_originals.begin(); itOriginals != block_originals.end(); ++itOriginals)
    {
        delete itOriginals->second;
    }
    block_originals.clear();
    for (NodenodeCacheType::const_iterator itCache = cache.begin(); itCache != cache.end(); ++itCache)
    {
        block_originals[itCache->first] = new CNameTrieNode(*(itCache->second));
    }
    namesToCheckForTakeover.clear();
    nCurrentHeight++;
    return true;
}

bool CNameTrieCache::decrementBlock(insertNameUndoType& insertUndo, NameQueueRowType& expireUndo, insertNameUndoType& insertSupportUndo, NamesupportQueueRowType& expireSupportUndo, std::vector<std::pair<std::string, int> >& takeoverHeightUndo) const
{
    LogPrintf("%s: nCurrentHeight (before decrement): %d\n", __func__, nCurrentHeight);
    nCurrentHeight--;
    
    if (expireSupportUndo.begin() != expireSupportUndo.end())
    {
        expirationNameQueueType::iterator itSupportExpireRow = getSupportExpirationQueueCacheRow(nCurrentHeight, true);
        for (NamesupportQueueRowType::iterator itSupportExpireUndo = expireSupportUndo.begin(); itSupportExpireUndo != expireSupportUndo.end(); ++itSupportExpireUndo)
        {
            insertSupportIntoMap(itSupportExpireUndo->first, itSupportExpireUndo->second, false);
            itSupportExpireRow->second.push_back(NameOutPointType(itSupportExpireUndo->first, itSupportExpireUndo->second.outPoint));
        }
    }
    
    for (insertNameUndoType::iterator itSupportUndo = insertSupportUndo.begin(); itSupportUndo != insertSupportUndo.end(); ++itSupportUndo)
    {
        supportNameQueueType::iterator itSupportRow = getSupportQueueCacheRow(itSupportUndo->nHeight, true);
        CSupportNameValue support;
        if(!removeSupportFromMap(itSupportUndo->name, itSupportUndo->outPoint, support, false))
            LogPrintf("removeSupportFromMap return false %d,%s\n",__LINE__,__func__);
        NamequeueNameType::iterator itSupportNameRow = getSupportQueueCacheNameRow(itSupportUndo->name, true);
        itSupportRow->second.push_back(std::make_pair(itSupportUndo->name, support));
        itSupportNameRow->second.push_back(NameoutPointHeightType(support.outPoint, support.nValidAtHeight));
    }
    
    if (expireUndo.begin() != expireUndo.end())
    {
        expirationNameQueueType::iterator itExpireRow = getExpirationQueueCacheRow(nCurrentHeight, true);
        for (NameQueueRowType::iterator itExpireUndo = expireUndo.begin(); itExpireUndo != expireUndo.end(); ++itExpireUndo)
        {
            insertClaimIntoTrie(itExpireUndo->first, itExpireUndo->second, false);
            itExpireRow->second.push_back(NameOutPointType(itExpireUndo->first, itExpireUndo->second.outPoint));
        }
    }

    for (insertNameUndoType::iterator itInsertUndo = insertUndo.begin(); itInsertUndo != insertUndo.end(); ++itInsertUndo)
    {
        nameQueueType::iterator itQueueRow = getQueueCacheRow(itInsertUndo->nHeight, true);
        CNameValue claim;
        if(!removeClaimFromTrie(itInsertUndo->name, itInsertUndo->outPoint, claim, false))
	{
            LogPrintf("removeClaimFromTrie return error %d,%s\n",__LINE__,__func__);
		return false;
	}
        NamequeueNameType::iterator itQueueNameRow = getQueueCacheNameRow(itInsertUndo->name, true);
        itQueueRow->second.push_back(std::make_pair(itInsertUndo->name, claim));
        itQueueNameRow->second.push_back(NameoutPointHeightType(itInsertUndo->outPoint, itInsertUndo->nHeight)); 
    }
    
    for (std::vector<std::pair<std::string, int> >::iterator itTakeoverHeightUndo = takeoverHeightUndo.begin(); itTakeoverHeightUndo != takeoverHeightUndo.end(); ++itTakeoverHeightUndo)
    {
        cacheTakeoverHeights[itTakeoverHeightUndo->first] = itTakeoverHeightUndo->second;
    }
    return true;
}

bool CNameTrieCache::finalizeDecrement() const
{
    for (NodenodeCacheType::iterator itOriginals = block_originals.begin(); itOriginals != block_originals.end(); ++itOriginals)
    {
        delete itOriginals->second;
    }
    block_originals.clear();
    for (NodenodeCacheType::const_iterator itCache = cache.begin(); itCache != cache.end(); ++itCache)
    {
        block_originals[itCache->first] = new CNameTrieNode(*(itCache->second));
    }
    return true;
}

bool CNameTrieCache::getLastTakeoverForName(const std::string& name, int& nLastTakeoverForName) const
{
    if (!fRequireTakeoverHeights)
    {
        nLastTakeoverForName = 0;
        return true;
    }
    std::map<std::string, int>::iterator itHeights = cacheTakeoverHeights.find(name);
    if (itHeights == cacheTakeoverHeights.end())
    {
        return base->getLastTakeoverForName(name, nLastTakeoverForName);
    }
    nLastTakeoverForName = itHeights->second;
    return true;
}

int CNameTrieCache::getNumBlocksOfContinuousOwnership(const std::string& name) const
{
    const CNameTrieNode* node = NULL;
    NodenodeCacheType::const_iterator itCache = cache.find(name);
    if (itCache != cache.end())
    {
        node = itCache->second;
    }
    if (!node)
    {
        node = base->getNodeForName(name);
    }
    if (!node || node->claims.empty())
    {
        return 0;
    }
    int nLastTakeoverHeight;
    if(!getLastTakeoverForName(name, nLastTakeoverHeight))
    {
        LogPrintf("getLastTakeoverForName return error %d,%s\n",__LINE__,__func__);
	return 0;
    }
    return nCurrentHeight - nLastTakeoverHeight;
}

int CNameTrieCache::getDelayForName(const std::string& name) const
{
    if (!fRequireTakeoverHeights)
    {
        return 0;
    }
    int nBlocksOfContinuousOwnership = getNumBlocksOfContinuousOwnership(name);
    return std::min(nBlocksOfContinuousOwnership / base->nProportionalDelayFactor, 4032);
}

uint256 CNameTrieCache::getBestBlock()
{
    if (hashBlock.IsNull())
        if (base != NULL)
            hashBlock = base->hashBlock;
    return hashBlock;
}

void CNameTrieCache::setBestBlock(const uint256& hashBlockIn)
{
    hashBlock = hashBlockIn;
}

bool CNameTrieCache::clear() const
{
    for (NodenodeCacheType::iterator itcache = cache.begin(); itcache != cache.end(); ++itcache)
    {
        delete itcache->second;
    }
    cache.clear();
    for (NodenodeCacheType::iterator itOriginals = block_originals.begin(); itOriginals != block_originals.end(); ++itOriginals)
    {
        delete itOriginals->second;
    }
    block_originals.clear();
    dirtyHashes.clear();
    cacheHashes.clear();
    claimQueueCache.clear();
    claimQueueNameCache.clear();
    expirationQueueCache.clear();
    supportCache.clear();
    supportQueueCache.clear();
    supportQueueNameCache.clear();
    namesToCheckForTakeover.clear();
    cacheTakeoverHeights.clear();
    return true;
}

bool CNameTrieCache::flush()
{
    if (dirty())
        getMerkleHash();
    bool success = base->update(cache, cacheHashes, cacheTakeoverHeights, getBestBlock(), claimQueueCache, claimQueueNameCache, expirationQueueCache, nCurrentHeight, supportCache, supportQueueCache, supportQueueNameCache, supportExpirationQueueCache);
    if (success)
    {
        success = clear();
    }
    return success;
}

uint256 CNameTrieCache::getLeafHashForProof(const std::string& currentPosition, unsigned char nodeChar, const CNameTrieNode* currentNode) const
{
    std::stringstream leafPosition;
    leafPosition << currentPosition << nodeChar;
    hashMapType::iterator cachedHash = cacheHashes.find(leafPosition.str());
    if (cachedHash != cacheHashes.end())
    {
        return cachedHash->second;
    }
    else
    {
        return currentNode->hash;
    }
}

CNameTrieProof CNameTrieCache::getProofForName(const std::string& name) const
{
    if (dirty())
        getMerkleHash();
    std::vector<CNameTrieProofNode> nodes;
    CNameTrieNode* current = &(base->root);
    NodenodeCacheType::const_iterator cachedNode;
    bool fNameHasValue = false;
    COutPoint outPoint;
    int nHeightOfLastTakeover = 0;
    for (std::string::const_iterator itName = name.begin(); current; ++itName)
    {
        std::string currentPosition(name.begin(), itName);
        cachedNode = cache.find(currentPosition);
        if (cachedNode != cache.end())
            current = cachedNode->second;
        CNameValue claim;
        bool fNodeHasValue = current->getBestClaim(claim);
        uint256 valueHash;
        if (fNodeHasValue)
        {
            int nHeightOfLastTakeover;
            if(!getLastTakeoverForName(currentPosition, nHeightOfLastTakeover))
	    {
                LogPrintf("getLastTakeoverForName return error %d,%s\n",__LINE__,__func__);
	    }
            valueHash = namegetValueHash(claim.outPoint, nHeightOfLastTakeover);
        }
        std::vector<std::pair<unsigned char, uint256> > children;
        CNameTrieNode* nextCurrent = NULL;
        for (nodeNameMapType::const_iterator itChildren = current->children.begin(); itChildren != current->children.end(); ++itChildren)
        {
            if (itName == name.end() || itChildren->first != *itName) // Leaf node
            {
                uint256 childHash = getLeafHashForProof(currentPosition, itChildren->first, itChildren->second);
                children.push_back(std::make_pair(itChildren->first, childHash));
            }
            else // Full node
            {
                nextCurrent = itChildren->second;
                uint256 childHash;
                children.push_back(std::make_pair(itChildren->first, childHash));
            }
        }
        if (currentPosition == name)
        {
            fNameHasValue = fNodeHasValue;
            if (fNameHasValue)
            {
                outPoint = claim.outPoint;
                if(!getLastTakeoverForName(name, nHeightOfLastTakeover))
                    LogPrintf("getLastTakeoverForName return false %d,%s\n",__LINE__,__func__);
            }
            valueHash.SetNull();
        }
        CNameTrieProofNode node(children, fNodeHasValue, valueHash);
        nodes.push_back(node);
        current = nextCurrent;
    }
    return CNameTrieProof(nodes, fNameHasValue, outPoint,
                           nHeightOfLastTakeover);
}
