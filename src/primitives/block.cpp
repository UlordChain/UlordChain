// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016-2018 The Ulord Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
//#include "crypto/common.h"

uint256 CBlockHeader::GetHash() const
{
//	return SerializeHash(*this);
	uint256 hash;

	CryptoHello(this, (unsigned char *)&hash);
	return hash;	
}

std::string CBlockHeader::ToString() const                                                                                                                                                                                                                                   
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, hashClaimTrie=%s, nTime=%u, nBits=%08x, nNonce=%u)\n",
		GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        hashClaimTrie.ToString(),
        nTime, nBits, nNonce);

    return s.str();
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, hashClaimTrie=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        hashClaimTrie.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (unsigned int i = 0; i < vtx.size(); i++)
    {
        s << "  " << vtx[i].ToString() << "\n";
    }
    return s.str();
}
