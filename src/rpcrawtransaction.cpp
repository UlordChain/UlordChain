// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sys/time.h>
#include "utilstrencodings.h"
#include "crypto/sha256.h"
#include "base58.h"
#include "chain.h"
#include "coins.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "init.h"
#include "keystore.h"
#include "main.h"
#include "merkleblock.h"
#include "net.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "rpcserver.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/sign.h"
#include "script/standard.h"
#include "txmempool.h"
#include "uint256.h"
#include "utilmoneystr.h"
#include "instantx.h"
#include "utiltime.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif
///////////////////////////////////////////////////////////
#include "arith_uint256.h"
#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include "nameclaim.h"
#include <time.h>
//////////////////////////////////////////////////////////
#include <stdint.h>

#include <boost/assign/list_of.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/foreach.hpp>
#include <univalue.h>

using namespace std;

typedef vector<unsigned char> valtype;

void ScriptPubKeyToJSON(const CScript& scriptPubKey, UniValue& out, bool fIncludeHex)
{
    txnouttype type;
    vector<CTxDestination> addresses;
    int nRequired;

    out.push_back(Pair("asm", ScriptToAsmStr(scriptPubKey)));
    if (fIncludeHex)
        out.push_back(Pair("hex", HexStr(scriptPubKey.begin(), scriptPubKey.end())));

    if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired)) {
        out.push_back(Pair("type", GetTxnOutputType(type)));
        return;
    }

    out.push_back(Pair("reqSigs", nRequired));
    out.push_back(Pair("type", GetTxnOutputType(type)));

    UniValue a(UniValue::VARR);
    BOOST_FOREACH(const CTxDestination& addr, addresses)
        a.push_back(CBitcoinAddress(addr).ToString());
    out.push_back(Pair("addresses", a));
}

void TxToJSON(const CTransaction& tx, const uint256 hashBlock, UniValue& entry)
{
    uint256 txid = tx.GetHash();
    entry.push_back(Pair("txid", txid.GetHex()));
    entry.push_back(Pair("size", (int)::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION)));
    entry.push_back(Pair("version", tx.nVersion));
    entry.push_back(Pair("locktime", (int64_t)tx.nLockTime));
    UniValue vin(UniValue::VARR);
    BOOST_FOREACH(const CTxIn& txin, tx.vin) {
        UniValue in(UniValue::VOBJ);
        if (tx.IsCoinBase())
            in.push_back(Pair("coinbase", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
        else {
            in.push_back(Pair("txid", txin.prevout.hash.GetHex()));
            in.push_back(Pair("vout", (int64_t)txin.prevout.n));
            UniValue o(UniValue::VOBJ);
            o.push_back(Pair("asm", ScriptToAsmStr(txin.scriptSig, true)));
            o.push_back(Pair("hex", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
            in.push_back(Pair("scriptSig", o));

            // Add address and value info if spentindex enabled
            CSpentIndexValue spentInfo;
            CSpentIndexKey spentKey(txin.prevout.hash, txin.prevout.n);
            if (GetSpentIndex(spentKey, spentInfo)) {
                in.push_back(Pair("value", ValueFromAmount(spentInfo.satoshis)));
                in.push_back(Pair("valueSat", spentInfo.satoshis));
                if (spentInfo.addressType == 1) {
                    in.push_back(Pair("address", CBitcoinAddress(CKeyID(spentInfo.addressHash)).ToString()));
                } else if (spentInfo.addressType == 2)  {
                    in.push_back(Pair("address", CBitcoinAddress(CScriptID(spentInfo.addressHash)).ToString()));
                }
            }

        }
        in.push_back(Pair("sequence", (int64_t)txin.nSequence));
        vin.push_back(in);
    }
    entry.push_back(Pair("vin", vin));
    UniValue vout(UniValue::VARR);
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& txout = tx.vout[i];
        UniValue out(UniValue::VOBJ);
        out.push_back(Pair("value", ValueFromAmount(txout.nValue)));
        out.push_back(Pair("valueSat", txout.nValue));
        out.push_back(Pair("n", (int64_t)i));
        UniValue o(UniValue::VOBJ);
        ScriptPubKeyToJSON(txout.scriptPubKey, o, true);
        out.push_back(Pair("scriptPubKey", o));

        // Add spent information if spentindex is enabled
        CSpentIndexValue spentInfo;
        CSpentIndexKey spentKey(txid, i);
        if (GetSpentIndex(spentKey, spentInfo)) {
            out.push_back(Pair("spentTxId", spentInfo.txid.GetHex()));
            out.push_back(Pair("spentIndex", (int)spentInfo.inputIndex));
            out.push_back(Pair("spentHeight", spentInfo.blockHeight));
        }

        vout.push_back(out);
    }
    entry.push_back(Pair("vout", vout));

    if (!hashBlock.IsNull()) {
        entry.push_back(Pair("blockhash", hashBlock.GetHex()));
        BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end() && (*mi).second) {
            CBlockIndex* pindex = (*mi).second;
            if (chainActive.Contains(pindex)) {
                entry.push_back(Pair("height", pindex->nHeight));
                entry.push_back(Pair("confirmations", 1 + chainActive.Height() - pindex->nHeight));
                entry.push_back(Pair("time", pindex->GetBlockTime()));
                entry.push_back(Pair("blocktime", pindex->GetBlockTime()));
            } else {
                entry.push_back(Pair("height", -1));
                entry.push_back(Pair("confirmations", 0));
            }
        }
    }
}

UniValue getrawtransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getrawtransaction \"txid\" ( verbose )\n"
            "\nNOTE: By default this function only works sometimes. This is when the tx is in the mempool\n"
            "or there is an unspent output in the utxo for this transaction. To make it always work,\n"
            "you need to maintain a transaction index, using the -txindex command line option.\n"
            "\nReturn the raw transaction data.\n"
            "\nIf verbose=0, returns a string that is serialized, hex-encoded data for 'txid'.\n"
            "If verbose is non-zero, returns an Object with information about 'txid'.\n"

            "\nArguments:\n"
            "1. \"txid\"      (string, required) The transaction id\n"
            "2. verbose       (numeric, optional, default=0) If 0, return a string, other return a json object\n"

            "\nResult (if verbose is not set or set to 0):\n"
            "\"data\"      (string) The serialized, hex-encoded data for 'txid'\n"

            "\nResult (if verbose > 0):\n"
            "{\n"
            "  \"hex\" : \"data\",       (string) The serialized, hex-encoded data for 'txid'\n"
            "  \"txid\" : \"id\",        (string) The transaction id (same as provided)\n"
            "  \"size\" : n,             (numeric) The transaction size\n"
            "  \"version\" : n,          (numeric) The version\n"
            "  \"locktime\" : ttt,       (numeric) The lock time\n"
            "  \"vin\" : [               (array of json objects)\n"
            "     {\n"
            "       \"txid\": \"id\",    (string) The transaction id\n"
            "       \"vout\": n,         (numeric) \n"
            "       \"scriptSig\": {     (json object) The script\n"
            "         \"asm\": \"asm\",  (string) asm\n"
            "         \"hex\": \"hex\"   (string) hex\n"
            "       },\n"
            "       \"sequence\": n      (numeric) The script sequence number\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "  \"vout\" : [              (array of json objects)\n"
            "     {\n"
            "       \"value\" : x.xxx,            (numeric) The value in " + CURRENCY_UNIT + "\n"
            "       \"n\" : n,                    (numeric) index\n"
            "       \"scriptPubKey\" : {          (json object)\n"
            "         \"asm\" : \"asm\",          (string) the asm\n"
            "         \"hex\" : \"hex\",          (string) the hex\n"
            "         \"reqSigs\" : n,            (numeric) The required sigs\n"
            "         \"type\" : \"pubkeyhash\",  (string) The type, eg 'pubkeyhash'\n"
            "         \"addresses\" : [           (json array of string)\n"
            "           \"ulordaddress\"        (string) ulord address\n"
            "           ,...\n"
            "         ]\n"
            "       }\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "  \"blockhash\" : \"hash\",   (string) the block hash\n"
            "  \"confirmations\" : n,      (numeric) The confirmations\n"
            "  \"time\" : ttt,             (numeric) The transaction time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"blocktime\" : ttt         (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("getrawtransaction", "\"mytxid\"")
            + HelpExampleCli("getrawtransaction", "\"mytxid\" 1")
            + HelpExampleRpc("getrawtransaction", "\"mytxid\", 1")
        );

    LOCK(cs_main);

    uint256 hash = ParseHashV(params[0], "parameter 1");

    bool fVerbose = false;
    if (params.size() > 1)
        fVerbose = (params[1].get_int() != 0);

    CTransaction tx;
    uint256 hashBlock;
    if (!GetTransaction(hash, tx, Params().GetConsensus(), hashBlock, true))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available about transaction");

    string strHex = EncodeHexTx(tx);

    if (!fVerbose)
        return strHex;

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hex", strHex));
    TxToJSON(tx, hashBlock, result);
    return result;
}

UniValue gettxoutproof(const UniValue& params, bool fHelp)
{
    if (fHelp || (params.size() != 1 && params.size() != 2))
        throw runtime_error(
            "gettxoutproof [\"txid\",...] ( blockhash )\n"
            "\nReturns a hex-encoded proof that \"txid\" was included in a block.\n"
            "\nNOTE: By default this function only works sometimes. This is when there is an\n"
            "unspent output in the utxo for this transaction. To make it always work,\n"
            "you need to maintain a transaction index, using the -txindex command line option or\n"
            "specify the block in which the transaction is included in manually (by blockhash).\n"
            "\nReturn the raw transaction data.\n"
            "\nArguments:\n"
            "1. \"txids\"       (string) A json array of txids to filter\n"
            "    [\n"
            "      \"txid\"     (string) A transaction hash\n"
            "      ,...\n"
            "    ]\n"
            "2. \"block hash\"  (string, optional) If specified, looks for txid in the block with this hash\n"
            "\nResult:\n"
            "\"data\"           (string) A string that is a serialized, hex-encoded data for the proof.\n"
        );

    set<uint256> setTxids;
    uint256 oneTxid;
    UniValue txids = params[0].get_array();
    for (unsigned int idx = 0; idx < txids.size(); idx++) {
        const UniValue& txid = txids[idx];
        if (txid.get_str().length() != 64 || !IsHex(txid.get_str()))
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid txid ")+txid.get_str());
        uint256 hash(uint256S(txid.get_str()));
        if (setTxids.count(hash))
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated txid: ")+txid.get_str());
       setTxids.insert(hash);
       oneTxid = hash;
    }

    LOCK(cs_main);

    CBlockIndex* pblockindex = NULL;

    uint256 hashBlock;
    if (params.size() > 1)
    {
        hashBlock = uint256S(params[1].get_str());
        if (!mapBlockIndex.count(hashBlock))
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        pblockindex = mapBlockIndex[hashBlock];
    } else {
        CCoins coins;
        if (pcoinsTip->GetCoins(oneTxid, coins) && coins.nHeight > 0 && coins.nHeight <= chainActive.Height())
            pblockindex = chainActive[coins.nHeight];
    }

    if (pblockindex == NULL)
    {
        CTransaction tx;
        if (!GetTransaction(oneTxid, tx, Params().GetConsensus(), hashBlock, false) || hashBlock.IsNull())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not yet in block");
        if (!mapBlockIndex.count(hashBlock))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Transaction index corrupt");
        pblockindex = mapBlockIndex[hashBlock];
    }

    CBlock block;
    if(!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus()))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");

    unsigned int ntxFound = 0;
    BOOST_FOREACH(const CTransaction&tx, block.vtx)
        if (setTxids.count(tx.GetHash()))
            ntxFound++;
    if (ntxFound != setTxids.size())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "(Not all) transactions not found in specified block");

    CDataStream ssMB(SER_NETWORK, PROTOCOL_VERSION);
    CMerkleBlock mb(block, setTxids);
    ssMB << mb;
    std::string strHex = HexStr(ssMB.begin(), ssMB.end());
    return strHex;
}

UniValue verifytxoutproof(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "verifytxoutproof \"proof\"\n"
            "\nVerifies that a proof points to a transaction in a block, returning the transaction it commits to\n"
            "and throwing an RPC error if the block is not in our best chain\n"
            "\nArguments:\n"
            "1. \"proof\"    (string, required) The hex-encoded proof generated by gettxoutproof\n"
            "\nResult:\n"
            "[\"txid\"]      (array, strings) The txid(s) which the proof commits to, or empty array if the proof is invalid\n"
        );

    CDataStream ssMB(ParseHexV(params[0], "proof"), SER_NETWORK, PROTOCOL_VERSION);
    CMerkleBlock merkleBlock;
    ssMB >> merkleBlock;

    UniValue res(UniValue::VARR);

    vector<uint256> vMatch;
    if (merkleBlock.txn.ExtractMatches(vMatch) != merkleBlock.header.hashMerkleRoot)
        return res;

    LOCK(cs_main);

    if (!mapBlockIndex.count(merkleBlock.header.GetHash()) || !chainActive.Contains(mapBlockIndex[merkleBlock.header.GetHash()]))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found in chain");

    BOOST_FOREACH(const uint256& hash, vMatch)
        res.push_back(hash.GetHex());
    return res;
}

UniValue createrawtransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw runtime_error(
            "createrawtransaction [{\"txid\":\"id\",\"vout\":n},...] {\"address\":amount,\"data\":\"hex\",...} ( locktime )\n"
            "\nCreate a transaction spending the given inputs and creating new outputs.\n"
            "Outputs can be addresses or data.\n"
            "Returns hex-encoded raw transaction.\n"
            "Note that the transaction's inputs are not signed, and\n"
            "it is not stored in the wallet or transmitted to the network.\n"

            "\nArguments:\n"
            "1. \"transactions\"        (string, required) A json array of json objects\n"
            "     [\n"
            "       {\n"
            "         \"txid\":\"id\",    (string, required) The transaction id\n"
            "         \"vout\":n        (numeric, required) The output number\n"
            "       }\n"
            "       ,...\n"
            "     ]\n"
            "2. \"outputs\"             (string, required) a json object with outputs\n"
            "    {\n"
            "      \"address\": x.xxx   (numeric or string, required) The key is the ulord address, the numeric value (can be string) is the " + CURRENCY_UNIT + " amount\n"
            "      \"data\": \"hex\",     (string, required) The key is \"data\", the value is hex encoded data\n"
            "      ...\n"
            "    }\n"
            "3. locktime                (numeric, optional, default=0) Raw locktime. Non-0 value also locktime-activates inputs\n"
            "\nResult:\n"
            "\"transaction\"            (string) hex string of the transaction\n"

            "\nExamples\n"
            + HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"{\\\"address\\\":0.01}\"")
            + HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"{\\\"data\\\":\\\"00010203\\\"}\"")
            + HelpExampleRpc("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\", \"{\\\"address\\\":0.01}\"")
            + HelpExampleRpc("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\", \"{\\\"data\\\":\\\"00010203\\\"}\"")
        );

    LOCK(cs_main);
    RPCTypeCheck(params, boost::assign::list_of(UniValue::VARR)(UniValue::VOBJ)(UniValue::VNUM), true);
    if (params[0].isNull() || params[1].isNull())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, arguments 1 and 2 must be non-null");

    UniValue inputs = params[0].get_array();
    UniValue sendTo = params[1].get_obj();

    CMutableTransaction rawTx;

    if (params.size() > 2 && !params[2].isNull()) {
        int64_t nLockTime = params[2].get_int64();
        if (nLockTime < 0 || nLockTime > std::numeric_limits<uint32_t>::max())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, locktime out of range");
        rawTx.nLockTime = nLockTime;
    }

    for (unsigned int idx = 0; idx < inputs.size(); idx++) {
        const UniValue& input = inputs[idx];
        const UniValue& o = input.get_obj();

        uint256 txid = ParseHashO(o, "txid");

        const UniValue& vout_v = find_value(o, "vout");
        if (!vout_v.isNum())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing vout key");
        int nOutput = vout_v.get_int();
        if (nOutput < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout must be positive");

        uint32_t nSequence = (rawTx.nLockTime ? std::numeric_limits<uint32_t>::max() - 1 : std::numeric_limits<uint32_t>::max());
        CTxIn in(COutPoint(txid, nOutput), CScript(), nSequence);

        rawTx.vin.push_back(in);
    }

    set<CBitcoinAddress> setAddress;
    vector<string> addrList = sendTo.getKeys();
    BOOST_FOREACH(const string& name_, addrList) {

        if (name_ == "data") {
            std::vector<unsigned char> data = ParseHexV(sendTo[name_].getValStr(),"Data");

            CTxOut out(0, CScript() << OP_RETURN << data);
            rawTx.vout.push_back(out);
        } else {
            CBitcoinAddress address(name_);
            if (!address.IsValid())
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid Ulord address: ")+name_);

            if (setAddress.count(address))
                throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+name_);
            setAddress.insert(address);

            CScript scriptPubKey = GetScriptForDestination(address.Get());
            CAmount nAmount = AmountFromValue(sendTo[name_]);

            CTxOut out(nAmount, scriptPubKey);
            rawTx.vout.push_back(out);
        }
    }

    return EncodeHexTx(rawTx);
}

UniValue decoderawtransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "decoderawtransaction \"hexstring\"\n"
            "\nReturn a JSON object representing the serialized, hex-encoded transaction.\n"

            "\nArguments:\n"
            "1. \"hex\"      (string, required) The transaction hex string\n"

            "\nResult:\n"
            "{\n"
            "  \"txid\" : \"id\",        (string) The transaction id\n"
            "  \"size\" : n,             (numeric) The transaction size\n"
            "  \"version\" : n,          (numeric) The version\n"
            "  \"locktime\" : ttt,       (numeric) The lock time\n"
            "  \"vin\" : [               (array of json objects)\n"
            "     {\n"
            "       \"txid\": \"id\",    (string) The transaction id\n"
            "       \"vout\": n,         (numeric) The output number\n"
            "       \"scriptSig\": {     (json object) The script\n"
            "         \"asm\": \"asm\",  (string) asm\n"
            "         \"hex\": \"hex\"   (string) hex\n"
            "       },\n"
            "       \"sequence\": n     (numeric) The script sequence number\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "  \"vout\" : [             (array of json objects)\n"
            "     {\n"
            "       \"value\" : x.xxx,            (numeric) The value in " + CURRENCY_UNIT + "\n"
            "       \"n\" : n,                    (numeric) index\n"
            "       \"scriptPubKey\" : {          (json object)\n"
            "         \"asm\" : \"asm\",          (string) the asm\n"
            "         \"hex\" : \"hex\",          (string) the hex\n"
            "         \"reqSigs\" : n,            (numeric) The required sigs\n"
            "         \"type\" : \"pubkeyhash\",  (string) The type, eg 'pubkeyhash'\n"
            "         \"addresses\" : [           (json array of string)\n"
            "           \"XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg\"   (string) Ulord address\n"
            "           ,...\n"
            "         ]\n"
            "       }\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("decoderawtransaction", "\"hexstring\"")
            + HelpExampleRpc("decoderawtransaction", "\"hexstring\"")
        );

    LOCK(cs_main);
    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR));

    CTransaction tx;

    if (!DecodeHexTx(tx, params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");

    UniValue result(UniValue::VOBJ);
    TxToJSON(tx, uint256(), result);

    return result;
}

UniValue decodescript(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "decodescript \"hex\"\n"
            "\nDecode a hex-encoded script.\n"
            "\nArguments:\n"
            "1. \"hex\"     (string) the hex encoded script\n"
            "\nResult:\n"
            "{\n"
            "  \"asm\":\"asm\",   (string) Script public key\n"
            "  \"hex\":\"hex\",   (string) hex encoded public key\n"
            "  \"type\":\"type\", (string) The output type\n"
            "  \"reqSigs\": n,    (numeric) The required signatures\n"
            "  \"addresses\": [   (json array of string)\n"
            "     \"address\"     (string) ulord address\n"
            "     ,...\n"
            "  ],\n"
            "  \"p2sh\",\"address\" (string) script address\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("decodescript", "\"hexstring\"")
            + HelpExampleRpc("decodescript", "\"hexstring\"")
        );

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR));

    UniValue r(UniValue::VOBJ);
    CScript script;
    if (params[0].get_str().size() > 0){
        vector<unsigned char> scriptData(ParseHexV(params[0], "argument"));
        script = CScript(scriptData.begin(), scriptData.end());
    } else {
        // Empty scripts are valid
    }
    ScriptPubKeyToJSON(script, r, false);

    r.push_back(Pair("p2sh", CBitcoinAddress(CScriptID(script)).ToString()));
    return r;
}

/** Pushes a JSON object for script verification or signing errors to vErrorsRet. */
static void TxInErrorToJSON(const CTxIn& txin, UniValue& vErrorsRet, const std::string& strMessage)
{
    UniValue entry(UniValue::VOBJ);
    entry.push_back(Pair("txid", txin.prevout.hash.ToString()));
    entry.push_back(Pair("vout", (uint64_t)txin.prevout.n));
    entry.push_back(Pair("scriptSig", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
    entry.push_back(Pair("sequence", (uint64_t)txin.nSequence));
    entry.push_back(Pair("error", strMessage));
    vErrorsRet.push_back(entry);
}

UniValue signrawtransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 4)
        throw runtime_error(
            "signrawtransaction \"hexstring\" ( [{\"txid\":\"id\",\"vout\":n,\"scriptPubKey\":\"hex\",\"redeemScript\":\"hex\"},...] [\"privatekey1\",...] sighashtype )\n"
            "\nSign inputs for raw transaction (serialized, hex-encoded).\n"
            "The second optional argument (may be null) is an array of previous transaction outputs that\n"
            "this transaction depends on but may not yet be in the block chain.\n"
            "The third optional argument (may be null) is an array of base58-encoded private\n"
            "keys that, if given, will be the only keys used to sign the transaction.\n"
#ifdef ENABLE_WALLET
            + HelpRequiringPassphrase() + "\n"
#endif

            "\nArguments:\n"
            "1. \"hexstring\"     (string, required) The transaction hex string\n"
            "2. \"prevtxs\"       (string, optional) An json array of previous dependent transaction outputs\n"
            "     [               (json array of json objects, or 'null' if none provided)\n"
            "       {\n"
            "         \"txid\":\"id\",             (string, required) The transaction id\n"
            "         \"vout\":n,                  (numeric, required) The output number\n"
            "         \"scriptPubKey\": \"hex\",   (string, required) script key\n"
            "         \"redeemScript\": \"hex\"    (string, required for P2SH) redeem script\n"
            "       }\n"
            "       ,...\n"
            "    ]\n"
            "3. \"privatekeys\"     (string, optional) A json array of base58-encoded private keys for signing\n"
            "    [                  (json array of strings, or 'null' if none provided)\n"
            "      \"privatekey\"   (string) private key in base58-encoding\n"
            "      ,...\n"
            "    ]\n"
            "4. \"sighashtype\"     (string, optional, default=ALL) The signature hash type. Must be one of\n"
            "       \"ALL\"\n"
            "       \"NONE\"\n"
            "       \"SINGLE\"\n"
            "       \"ALL|ANYONECANPAY\"\n"
            "       \"NONE|ANYONECANPAY\"\n"
            "       \"SINGLE|ANYONECANPAY\"\n"

            "\nResult:\n"
            "{\n"
            "  \"hex\" : \"value\",           (string) The hex-encoded raw transaction with signature(s)\n"
            "  \"complete\" : true|false,   (boolean) If the transaction has a complete set of signatures\n"
            "  \"errors\" : [                 (json array of objects) Script verification errors (if there are any)\n"
            "    {\n"
            "      \"txid\" : \"hash\",           (string) The hash of the referenced, previous transaction\n"
            "      \"vout\" : n,                (numeric) The index of the output to spent and used as input\n"
            "      \"scriptSig\" : \"hex\",       (string) The hex-encoded signature script\n"
            "      \"sequence\" : n,            (numeric) Script sequence number\n"
            "      \"error\" : \"text\"           (string) Verification or signing error related to the input\n"
            "    }\n"
            "    ,...\n"
            "  ]\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("signrawtransaction", "\"myhex\"")
            + HelpExampleRpc("signrawtransaction", "\"myhex\"")
        );

#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwalletMain ? &pwalletMain->cs_wallet : NULL);
#else
    LOCK(cs_main);
#endif
    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VARR)(UniValue::VARR)(UniValue::VSTR), true);

    vector<unsigned char> txData(ParseHexV(params[0], "argument 1"));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    vector<CMutableTransaction> txVariants;
    while (!ssData.empty()) {
        try {
            CMutableTransaction tx;
            ssData >> tx;
            txVariants.push_back(tx);
        }
        catch (const std::exception&) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
        }
    }

    if (txVariants.empty())
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Missing transaction");

    // mergedTx will end up with all the signatures; it
    // starts as a clone of the rawtx:
    CMutableTransaction mergedTx(txVariants[0]);

    // Fetch previous transactions (inputs):
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);
    {
        LOCK(mempool.cs);
        CCoinsViewCache &viewChain = *pcoinsTip;
        CCoinsViewMemPool viewMempool(&viewChain, mempool);
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view

        BOOST_FOREACH(const CTxIn& txin, mergedTx.vin) {
            const uint256& prevHash = txin.prevout.hash;
            CCoins coins;
            view.AccessCoins(prevHash); // this is certainly allowed to fail
        }

        view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
    }

    bool fGivenKeys = false;
    CBasicKeyStore tempKeystore;
    if (params.size() > 2 && !params[2].isNull()) {
        fGivenKeys = true;
        UniValue keys = params[2].get_array();
        for (unsigned int idx = 0; idx < keys.size(); idx++) {
            UniValue k = keys[idx];
            CBitcoinSecret vchSecret;
            bool fGood = vchSecret.SetString(k.get_str());
            if (!fGood)
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
            CKey key = vchSecret.GetKey();
            if (!key.IsValid())
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Private key outside allowed range");
            tempKeystore.AddKey(key);
        }
    }
#ifdef ENABLE_WALLET
    else if (pwalletMain)
        EnsureWalletIsUnlocked();
#endif

    // Add previous txouts given in the RPC call:
    if (params.size() > 1 && !params[1].isNull()) {
        UniValue prevTxs = params[1].get_array();
        for (unsigned int idx = 0; idx < prevTxs.size(); idx++) {
            const UniValue& p = prevTxs[idx];
            if (!p.isObject())
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "expected object with {\"txid'\",\"vout\",\"scriptPubKey\"}");

            UniValue prevOut = p.get_obj();

            RPCTypeCheckObj(prevOut, boost::assign::map_list_of("txid", UniValue::VSTR)("vout", UniValue::VNUM)("scriptPubKey", UniValue::VSTR));

            uint256 txid = ParseHashO(prevOut, "txid");

            int nOut = find_value(prevOut, "vout").get_int();
            if (nOut < 0)
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "vout must be positive");

            vector<unsigned char> pkData(ParseHexO(prevOut, "scriptPubKey"));
            CScript scriptPubKey(pkData.begin(), pkData.end());

            {
                CCoinsModifier coins = view.ModifyCoins(txid);
                if (coins->IsAvailable(nOut) && coins->vout[nOut].scriptPubKey != scriptPubKey) {
                    string err("Previous output scriptPubKey mismatch:\n");
                    err = err + ScriptToAsmStr(coins->vout[nOut].scriptPubKey) + "\nvs:\n"+
                        ScriptToAsmStr(scriptPubKey);
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, err);
                }
                if ((unsigned int)nOut >= coins->vout.size())
                    coins->vout.resize(nOut+1);
                coins->vout[nOut].scriptPubKey = scriptPubKey;
                coins->vout[nOut].nValue = 0; // we don't know the actual output value
            }

            // if redeemScript given and not using the local wallet (private keys
            // given), add redeemScript to the tempKeystore so it can be signed:
            if (fGivenKeys && scriptPubKey.IsPayToScriptHash()) {
                RPCTypeCheckObj(prevOut, boost::assign::map_list_of("txid", UniValue::VSTR)("vout", UniValue::VNUM)("scriptPubKey", UniValue::VSTR)("redeemScript",UniValue::VSTR));
                UniValue v = find_value(prevOut, "redeemScript");
                if (!v.isNull()) {
                    vector<unsigned char> rsData(ParseHexV(v, "redeemScript"));
                    CScript redeemScript(rsData.begin(), rsData.end());
                    tempKeystore.AddCScript(redeemScript);
                }
            }
        }
    }

#ifdef ENABLE_WALLET
    const CKeyStore& keystore = ((fGivenKeys || !pwalletMain) ? tempKeystore : *pwalletMain);
#else
    const CKeyStore& keystore = tempKeystore;
#endif

    int nHashType = SIGHASH_ALL;
    if (params.size() > 3 && !params[3].isNull()) {
        static map<string, int> mapSigHashValues =
            boost::assign::map_list_of
            (string("ALL"), int(SIGHASH_ALL))
            (string("ALL|ANYONECANPAY"), int(SIGHASH_ALL|SIGHASH_ANYONECANPAY))
            (string("NONE"), int(SIGHASH_NONE))
            (string("NONE|ANYONECANPAY"), int(SIGHASH_NONE|SIGHASH_ANYONECANPAY))
            (string("SINGLE"), int(SIGHASH_SINGLE))
            (string("SINGLE|ANYONECANPAY"), int(SIGHASH_SINGLE|SIGHASH_ANYONECANPAY))
            ;
        string strHashType = params[3].get_str();
        if (mapSigHashValues.count(strHashType))
            nHashType = mapSigHashValues[strHashType];
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid sighash param");
    }

    bool fHashSingle = ((nHashType & ~SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE);

    // Script verification errors
    UniValue vErrors(UniValue::VARR);

    // Sign what we can:
    for (unsigned int i = 0; i < mergedTx.vin.size(); i++) {
        CTxIn& txin = mergedTx.vin[i];
        const CCoins* coins = view.AccessCoins(txin.prevout.hash);
        if (coins == NULL || !coins->IsAvailable(txin.prevout.n)) {
            TxInErrorToJSON(txin, vErrors, "Input not found or already spent");
            continue;
        }
        const CScript& prevPubKey = coins->vout[txin.prevout.n].scriptPubKey;

        txin.scriptSig.clear();
        // Only sign SIGHASH_SINGLE if there's a corresponding output:
        if (!fHashSingle || (i < mergedTx.vout.size()))
            SignSignature(keystore, prevPubKey, mergedTx, i, nHashType);

        // ... and merge in other signatures:
        BOOST_FOREACH(const CMutableTransaction& txv, txVariants) {
            txin.scriptSig = CombineSignatures(prevPubKey, mergedTx, i, txin.scriptSig, txv.vin[i].scriptSig);
        }
        ScriptError serror = SCRIPT_ERR_OK;
        if (!VerifyScript(txin.scriptSig, prevPubKey, STANDARD_SCRIPT_VERIFY_FLAGS, MutableTransactionSignatureChecker(&mergedTx, i), &serror)) {
            TxInErrorToJSON(txin, vErrors, ScriptErrorString(serror));
        }
    }
    bool fComplete = vErrors.empty();

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hex", EncodeHexTx(mergedTx)));
    result.push_back(Pair("complete", fComplete));
    if (!vErrors.empty()) {
        result.push_back(Pair("errors", vErrors));
    }

    return result;
}

UniValue sendrawtransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "sendrawtransaction \"hexstring\" ( allowhighfees instantsend )\n"
            "\nSubmits raw transaction (serialized, hex-encoded) to local node and network.\n"
            "\nAlso see createrawtransaction and signrawtransaction calls.\n"
            "\nArguments:\n"
            "1. \"hexstring\"    (string, required) The hex string of the raw transaction)\n"
            "2. allowhighfees  (boolean, optional, default=false) Allow high fees\n"
            "3. instantsend    (boolean, optional, default=false) Use InstantSend to send this transaction\n"
            "\nResult:\n"
            "\"hex\"             (string) The transaction hash in hex\n"
            "\nExamples:\n"
            "\nCreate a transaction\n"
            + HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\" : \\\"mytxid\\\",\\\"vout\\\":0}]\" \"{\\\"myaddress\\\":0.01}\"") +
            "Sign the transaction, and get back the hex\n"
            + HelpExampleCli("signrawtransaction", "\"myhex\"") +
            "\nSend the transaction (signed hex)\n"
            + HelpExampleCli("sendrawtransaction", "\"signedhex\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("sendrawtransaction", "\"signedhex\"")
        );

    LOCK(cs_main);
    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VBOOL)(UniValue::VBOOL));

    // parse hex string from parameter
    CTransaction tx;
    if (!DecodeHexTx(tx, params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    uint256 hashTx = tx.GetHash();

    bool fOverrideFees = false;
    if (params.size() > 1)
        fOverrideFees = params[1].get_bool();

    bool fInstantSend = false;
    if (params.size() > 2)
        fInstantSend = params[2].get_bool();

    CCoinsViewCache &view = *pcoinsTip;
    const CCoins* existingCoins = view.AccessCoins(hashTx);
    bool fHaveMempool = mempool.exists(hashTx);
    bool fHaveChain = existingCoins && existingCoins->nHeight < 1000000000;
    if (!fHaveMempool && !fHaveChain) {
        // push to local node and sync with wallets
        CValidationState state;
        bool fMissingInputs;
        if (!AcceptToMemoryPool(mempool, state, tx, false, &fMissingInputs, false, !fOverrideFees)) {
            if (state.IsInvalid()) {
                throw JSONRPCError(RPC_TRANSACTION_REJECTED, strprintf("%i: %s", state.GetRejectCode(), state.GetRejectReason()));
            } else {
                if (fMissingInputs) {
                    throw JSONRPCError(RPC_TRANSACTION_ERROR, "Missing inputs");
                }
                throw JSONRPCError(RPC_TRANSACTION_ERROR, state.GetRejectReason());
            }
        }
    } else if (fHaveChain) {
        throw JSONRPCError(RPC_TRANSACTION_ALREADY_IN_CHAIN, "transaction already in block chain");
    }
    if (fInstantSend && !instantsend.ProcessTxLockRequest(tx)) {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, "Not a valid InstantSend transaction, see debug.log for more info");
    }
    RelayTransaction(tx);

    return hashTx.GetHex();
}

#ifdef ENABLE_WALLET
UniValue crosschaininitial(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() !=2)
        throw runtime_error(
            "crosschaininitial \"crosschain address\" amount\n"
            "\nCreate crosschain transaction (serialized, hex-encoded) to local node and network.\n"
            "\nArguments:\n"
	    "1. \"crosschain address\"  (string,required) The crosschainaddress to to send to .\n"
            "2. \"amount\" (numeric or string,required) The amount in " + CURRENCY_UNIT + " to send. eg 0.1\n"
            "\nResult:\n"
	    "\"hex\"             (string) The secret in hex\n"
            "\"hex\"             (string) The secret hash in hex\n"
            "\"hex\"             (string) The contract for address in hex\n"
            "\"hex\"             (string) The contract transaction hash in hex\n"
            "\"hex\"             (string) The contract raw transaction in hex\n"
            "\nExamples:\n"
            "\nCreate a transaction\n"
            + HelpExampleCli("crosschaininitial", "\"XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg\" 0.1")
        );
	// parse parameters
	if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;
	LOCK2(cs_main, pwalletMain->cs_wallet);
	CBitcoinAddress address(params[0].get_str());
	if (!address.IsValid())
    	throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Ulord address");

	// Amount
    CAmount nAmount = AmountFromValue(params[1]);
    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");

	// a random value is generated and sha256 hash algorithm is used.
	unsigned char vch[32];
	memset(vch, 0x00, sizeof(vch));
	RandAddSeedPerfmon();
    GetRandBytes(vch, sizeof(vch));
	uint256 secret = Hash(vch,vch+sizeof(vch));
	std::string tem = secret.GetHex();
	std::vector<unsigned char>str_hash(tem.begin(),tem.end());
	
	uint160 secret_hash = Hash160(str_hash);
	std::string hash_tem = secret_hash.GetHex();
  	CBitcoinAddress hash_address;
	hash_address.Set((CScriptID&)secret_hash);

	// Gets the current Unix timestamp.(hex)
	struct timeval tm;
	gettimeofday(&tm,NULL);
    // 172800 is 48hour to second
	int64_t l_time = tm.tv_sec + 172800;
	// construct contract of script
	CPubKey newKey;
    if ( !pwalletMain->GetKeyFromPool(newKey) )
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT,"Error: Keypool ran out,please call keypoolrefill first");
	 uint160 refund =  newKey.gethash();
	uint160 addr = address.GetData();

	CScript contract =  CScript() << OP_IF << OP_RIPEMD160 << ToByteVector(secret_hash) << OP_EQUALVERIFY << OP_DUP << OP_HASH160 \
	<< ToByteVector(addr) << OP_ELSE << l_time << OP_CHECKLOCKTIMEVERIFY << OP_DROP << OP_DUP << OP_HASH160\
	<< ToByteVector(refund) << OP_ENDIF << OP_EQUALVERIFY << OP_CHECKSIG;
	
	// The build script is 160 hashes.
	CScriptID contractP2SH = CScriptID(contract);
	CBitcoinAddress contract_address;
	contract_address.Set(contractP2SH);	
	// Start building the lock script for the p2sh type.
	CScript contractP2SHPkScript = GetScriptForDestination(CTxDestination(contractP2SH));

	// The amount is locked in the redemption script.
	 vector<CRecipient> vecSend;
    int nChangePosRet = -1;
    CRecipient recipient = {contractP2SHPkScript,nAmount,false};
    vecSend.push_back(recipient);

	// Start building a deal
	CReserveKey reservekey(pwalletMain);
	CAmount nFeeRequired = 0;
    std::string strError;
	CWalletTx wtxNew;
	if ( !pwalletMain->CreateTransaction(vecSend,wtxNew,reservekey,nFeeRequired,nChangePosRet,strError))
		{
			if ( nAmount + nFeeRequired > pwalletMain->GetBalance() )
			{
				strError = strprintf("Error: This transaction requires a transaction fee of at leasst %s because if its amount, complex, or use of recently received funds!",FormatMoney(nFeeRequired));
			}
			LogPrintf("%s() : %s\n",__func__,strError);
			throw JSONRPCError(RPC_WALLET_ERROR,strError);
		}
			
		if ( !pwalletMain->CommitTransaction(wtxNew,reservekey) )
			throw JSONRPCError(RPC_WALLET_ERROR,"Error: The transaction was rejected! This might hapen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
	
	UniValue result(UniValue::VOBJ);
	CBitcoinAddress refund_address;
	refund_address.Set(CKeyID(refund));
	result.push_back(Pair("refund_address",refund_address.ToString()));
	result.push_back(Pair("hexstring",wtxNew.GetHash().GetHex()));
	result.push_back(Pair("hex",EncodeHexTx(wtxNew)));
	result.push_back(Pair("Contract(address) ",contract_address.ToString()));
	result.push_back(Pair("contract",HexStr(contract.begin(),contract.end())));
	result.push_back(Pair("secret",secret.ToString()));
	result.push_back(Pair("secrethash",secret_hash.ToString()));
    return result;
}

UniValue crosschainparticipate(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() !=3)
        throw runtime_error(
	    "crosschaininitial \"crosschain address\"amount \"secret address \n"
            "\nCreate crosschain transaction (serialized, hex-encoded) to local node and network.\n"
	    "\nArguments:\n"
            "1. \"crosschain address\"  (string,required) The crosschainaddress to to send to .\n"
            "2. \"amount\" (numeric or string,required) The amount in " + CURRENCY_UNIT + " to send. eg 0.1\n"
            "3. \"secret address \" (string,required) The secret address. \n"
	    "\nResult:\n"
            "\"hex\"             (string) The contract for address in hex\n"
            "\"hex\"             (string) The contract hash in hex\n"
            "\"hex\"             (string) The contract transaction hash in hex\n"
            "\"hex\"             (string) The contract raw transaction in hex\n"
            "\nExamples:\n"
            "\nCreate a transaction\n"
            + HelpExampleCli("crosschaininitial", "\"XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg\",\
            				sbd6vhmcrBGdPmyuffYvkfyzxJnD7m2ePf ")
        );
    // parse parameters
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    CBitcoinAddress address(params[0].get_str());
    if (!address.IsValid())
    	throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Ulord address");

    // Amount
    CAmount nAmount = AmountFromValue(params[1]);
    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
	std::vector<unsigned char>secret_hash;
	std::vector<unsigned char> u_base = ParseHex(params[2].get_str());
	string str_temp(u_base.begin(),u_base.end());
	DecodeBase58(str_temp, secret_hash);
	cout << params[2].get_str() << endl;
	
	// Gets the current Unix timestamp.(hex)
	struct timeval tm;
	gettimeofday(&tm,NULL);
    // 86400 is 24hour to second
	int64_t l_time = tm.tv_sec + 86400;
	
	// construct contract of script
	CPubKey newKey;
    if ( !pwalletMain->GetKeyFromPool(newKey) )
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT,"Error: Keypool ran out,please call keypoolrefill first");
	uint160 refund =  newKey.gethash();
	uint160 addr = address.GetData();

	CScript contract =  CScript() << OP_IF << OP_RIPEMD160 << ToByteVector(secret_hash) << OP_EQUALVERIFY << OP_DUP << OP_HASH160 \
	<< ToByteVector(addr) << OP_ELSE << l_time << OP_CHECKLOCKTIMEVERIFY << OP_DROP << OP_DUP << OP_HASH160\
	<< ToByteVector(refund) << OP_ENDIF << OP_EQUALVERIFY << OP_CHECKSIG;
    
	// The build script is 160 hashes.
	CScriptID contractP2SH = CScriptID(contract);
	CBitcoinAddress contract_address;
	contract_address.Set(contractP2SH);	
	// Start building the lock script for the p2sh type.
	CScript contractP2SHPkScript = GetScriptForDestination(CTxDestination(contractP2SH));

	// The amount is locked in the redemption script.
	 vector<CRecipient> vecSend;
    int nChangePosRet = -1;
    CRecipient recipient = {contractP2SHPkScript,nAmount,false};
    vecSend.push_back(recipient);

	// Start building a deal
	CReserveKey reservekey(pwalletMain);
	CAmount nFeeRequired = 0;
    std::string strError;
	CWalletTx wtxNew;
	if ( !pwalletMain->CreateTransaction(vecSend,wtxNew,reservekey,nFeeRequired,nChangePosRet,strError))
	{
		if ( nAmount + nFeeRequired > pwalletMain->GetBalance() )
		{
			strError = strprintf("Error: This transaction requires a transaction fee of at leasst %s because if its amount, complex, or use of recently received funds!",FormatMoney(nFeeRequired));
		}
		LogPrintf("%s() : %s\n",__func__,strError);
		throw JSONRPCError(RPC_WALLET_ERROR,strError);
	}
		
	if ( !pwalletMain->CommitTransaction(wtxNew,reservekey) )
		throw JSONRPCError(RPC_WALLET_ERROR,"Error: The transaction was rejected! This might hapen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");

	CBitcoinAddress refund_address;
	refund_address.Set(CKeyID(refund));


	UniValue result(UniValue::VOBJ);
	result.push_back(Pair("refund_address",refund_address.ToString()));
	result.push_back(Pair("hexstring",wtxNew.GetHash().GetHex()));
	result.push_back(Pair("hex",EncodeHexTx(wtxNew)));
	result.push_back(Pair("Contract(address) ",contract_address.ToString()));
	result.push_back(Pair("contract",HexStr(contract.begin(),contract.end())));

	return result;

}
UniValue crosschainredeem(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() !=3)
        throw runtime_error(
            "crosschainredeem \"contract\" \"contract transaction\" \"secret\" \n"
            "\nCreate crosschain redeem transaction (serialized, hex-encoded) to local node and network.\n"
            "\nArguments:\n"
            "1. \"contract \"  (string,required) The contract in hex\n"
            "2. \"contract transaction \"  (string,required) The contract raw transaction in hex\n"
            "3. \"secret \"  (string,required) (string,required) The secret in hex\n"
            "nResult:\n"
            "\"Redeem fee\"      (string) The Redeem fee of redeem transacton\n"
            "\"hex\"             (string) The redeem transaction hash in hex\n"
            "\"hex\"             (string) The redeem raw transaction in hex\n"
			"\nExamples:\n"
			"\nCreate a redeem transaction\n"
            + HelpExampleCli("crosschainredeem", "\"63a6148887e0860cc6d28972b4622e9f2e1c2bc4fce57a8876a9140a836d8ee19150b965b93a8724e65a79d73100306704f9e50b5bb17576a914de71cb447f326f3a70f9da4a8369ad3068a3493f6888ac \"0100000002355bfc80e5e4d14c634131a30f121a49b27daec201b592d0079247d189dba9a2000000006b483045022100c3ebf9d0a2b44c0a20b84b37bce495f91de3ebd706de9a15cecf77548d2c1a3002203970002c5493b170bd375010b8876799af721a07900c6eb4ee7c21c140469922012103942f6cd9b855c565acd40406a692d39805eef3ab38ec56166afb6d04b071fc21feffffffcb53ff98a0d504249b04c8fe829e9a0c3bd468caeaaba50f3da6d16b0b69eaf3000000006a4730440220138197f27a806028f3bd885aa0e0fecd3b9e2cce43f09d18ed7219e5a087ab0e022075e18b7a8031d340ef2f97fd2efef3a51fbe1b0a2ae04cb76f3ba4ca500e895b01210286921478ed27357ee44f5a5340b051a33b84f5654b7c1d3ec5da2dc9f39d6e3afeffffff02a0850b54020000001976a9142488e2ce9de4952ce739d5cb0df3f2f6bae2395c88ac00e40b540200000017a914babe4713f8e43291e490f738e1b38474440be152872c010000 \"e93e589dda24433fcac88a42b995ad24bafe3b5acd45d71bd66a8feedab27a70\"")
        );
    UniValue result(UniValue::VOBJ);

	LOCK(cs_main);
	RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VSTR)(UniValue::VSTR));

    //check params size
    if ((params[0].get_str().size() <= 0)||(params[1].get_str().size() <= 0)||(params[2].get_str().size() <= 0))
		{
			throw JSONRPCError(RPC_INVALID_PARAMS, "Error:the parameter size can't be zero");
		}
	//get the contract from parameter 0
	string strContract = params[0].get_str();
    std::vector<unsigned char>vContract = ParseHex(strContract);
	CScript contract(vContract.begin(),vContract.end());

	//split the contract
	std::string contractString	= ScriptToAsmStr(contract);
    std::vector<std::string> vStr;
    boost::split( vStr, contractString, boost::is_any_of( " " ), boost::token_compress_on );

    //contract check
	if(!contract.IsCrossChainPaymentScript())
		{
			return JSONRPCError(RPC_INVALID_PARAMS, "Error:the parameter is no stander contract");
		}	

	//get participent address hash
	std::vector<unsigned char> vParticipentAddressHash = ParseHex(vStr[6]);
    uint160 participentAddressHash(vParticipentAddressHash);

    //decode the tx
	CTransaction preTx;
	if (!DecodeHexTx(preTx, params[1].get_str()))
       return JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");

	//get secret hash from contract
	std::vector<unsigned char> contractSecretHash = ParseHex(vStr[2]);
    uint160 uContractSecretHash(contractSecretHash);	

    //get secret form parameter 2
	std::vector<unsigned char> secretVector =ParseHexV(params[2], "secret");

	//check the secret in parameter and in contract
	std::vector<unsigned char> transactionSecretHash(20);
	CRIPEMD160().Write(begin_ptr(secretVector), secretVector.size()).Finalize(begin_ptr(transactionSecretHash));
	uint160 uTransactionSecretHash(transactionSecretHash);
	if ( 0 != strcmp(uContractSecretHash.ToString().c_str(),uTransactionSecretHash.ToString().c_str()) )
		{
			return JSONRPCError(RPC_INVALID_PARAMS, "Error:the secret in parameter not match in in contract");		
		}

	//declare transaction
	CMutableTransaction txNew;
	CAmount nFeePay = 3100;

    //get the redeem txin
	CAmount preOutAmount = 0;
	COutPoint preOutPoint;
	uint256 preTxid = preTx.GetHash();
	CTxOut preTxOut;
	uint32_t preOutN =0;	
	std::vector<valtype> vSolutions;
	txnouttype addressType = TX_NONSTANDARD;
	uint160 addrhash;

	//get the previous tx ouput
	BOOST_FOREACH(const CTxOut& txout, preTx.vout) 
	{
		const CScript scriptPubkey = StripClaimScriptPrefix(txout.scriptPubKey);
		if (Solver(scriptPubkey, addressType, vSolutions))
		{
	        if(addressType== TX_SCRIPTHASH )
	        {
	            addrhash=uint160(vSolutions[0]);
				preOutAmount =  txout.nValue;
				CTxIn tmptxin = CTxIn(preTxid,preOutN,CScript());
				tmptxin.prevPubKey = txout.scriptPubKey;
				txNew.vin.push_back(tmptxin);
				break;	
	        }
		}
		preOutN++;
	}
	//check the previous tx output type
	if(addressType !=TX_SCRIPTHASH)
		{
			return JSONRPCError(RPC_INVALID_PARAMS, "Error:the transaction have none P2SH type tx out");	
		}

	//check the contract is match transaction or not 
	if ( 0 != strcmp(addrhash.ToString().c_str(),Hash160(vContract).ToString().c_str()) )
	{
		return JSONRPCError(RPC_INVALID_PARAMS, "Error:the contract in parameter can't match transaction in parameter");
	}

	//get the pubkey and key of participate address
	const CKeyStore& keystore = *pwalletMain;
	CKeyID keyID(participentAddressHash);
	CPubKey pubKey;
	CKey key;	
	if(!keystore.GetPubKey(keyID,pubKey))
		{
			return JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error:Can't find the pubkey of participte address");			
		}
	if(!keystore.GetKey(keyID,key))
		{
			return JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error:Can't find the key of participte address");	
		}

    //get the out pubkey type p2pkh
    CReserveKey reservekey(pwalletMain);
    CPubKey newKey;
	bool ret;
	ret = reservekey.GetReservedKey(newKey);
	assert(ret);
    CBitcoinAddress outPutAddress(CTxDestination(newKey.GetID()));
    if (!outPutAddress.IsValid())
        return JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error:Invalid Ulord address");

	// Start building the lock script for the p2pkh type.
	CScript paritipantP2PkHScript = GetScriptForDestination(CTxDestination(newKey.GetID()));
	CAmount nAmount = preOutAmount- nFeePay;
	CTxOut outNew(nAmount,paritipantP2PkHScript);
	txNew.vout.push_back(outNew);

	txNew.nLockTime = chainActive.Height();
	txNew.nVersion = 1;

	// Sign the redeem transaction
	CTransaction txNewConst(txNew);
	std::vector<unsigned char> vchSig;
	CScript scriptSigRs;
	uint256 hash = SignatureHash(contract, txNew, 0, SIGHASH_ALL);
	bool signSuccess = key.Sign(hash, vchSig);
    bool verifySuccess = pubKey.Verify(hash,vchSig);
    vchSig.push_back((unsigned char)SIGHASH_ALL);	

	if(signSuccess)
		{
		CScript script1 =CScript() <<ToByteVector(vchSig);
		CScript script2 =CScript() << ToByteVector(pubKey);
		CScript script3 =CScript() <<ToByteVector(secretVector);
		CScript script4 =CScript() << OP_TRUE <<ToByteVector(vContract);
		scriptSigRs= script1 + script2 + script3 + script4;
		txNew.vin[0].scriptSig = scriptSigRs;		
		}
	else
		{
			return JSONRPCError(RPC_INTERNAL_ERROR, "ERROR:sign transaction error");
		}

	if(!verifySuccess)
		{
			return JSONRPCError(RPC_INTERNAL_ERROR, "ERROR:verify the sign of transaction error");
		}

    //serialize and get the size of transaction
	unsigned int nBytes = ::GetSerializeSize(txNew, SER_NETWORK, PROTOCOL_VERSION);

	//check limit size
	if (nBytes >= MAX_STANDARD_TX_SIZE)
	{
		return JSONRPCError(RPC_INTERNAL_ERROR, "ERROR:transaction too large");
	}

    //Is Dust
	if (txNew.vout[0].IsDust(::minRelayTxFee))
	{
		return JSONRPCError(RPC_INTERNAL_ERROR, "ERROR:transaction is dust transaction");
	}

	//commit the transaction 
     CWalletTx wtxNew;
	 wtxNew.fTimeReceivedIsTxTime = true;
     wtxNew.BindWallet(pwalletMain);
	 wtxNew.fFromMe = true;
	*static_cast<CTransaction*>(&wtxNew) = CTransaction(txNew);

	if (!pwalletMain->CommitTransaction(wtxNew, reservekey,NetMsgType::TX))
			return JSONRPCError(RPC_WALLET_ERROR, "Transaction commit failed");	

	double fFeePay = (double)nFeePay;
	string strRedeemFee = strprintf("Redeem fee: %.8f UT(%.8f UT/kB)\n", (fFeePay / COIN), ((fFeePay / COIN)/nBytes));

	result.push_back(Pair("Redeem fee",strRedeemFee));
	result.push_back(Pair("Redeem transaction hash",CTransaction(txNew).GetHash().GetHex()));
	result.push_back(Pair("Redeem transaction",EncodeHexTx(CTransaction(txNew))));
    return result;
}
UniValue crosschainrefund(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() !=2)
        throw runtime_error(
		"crosschainrefund \"contract \"contract transaction \n"
		"\nCreate crosschain refund transaction (serialized, hex-encoded) to local node and network.\n"
		"\nArguments:\n"
		"1. \"contract \"  (string,required) The contract in hex\n"
		"2. \"contract transaction \"  (string,required) The contract raw transaction in hex\n"
		"nResult:\n"
		"\"Refund fee\" 	 (string) The refund fee of redeem transacton\n"
		"\"hex\"			 (string) The refund transaction hash in hex\n"
		"\"hex\"			 (string) The refund raw transaction in hex\n"
		"\nExamples:\n"
		"\nCreate a refund transaction\n"
		+ HelpExampleCli("crosschainrefund", "63a6148887e0860cc6d28972b4622e9f2e1c2bc4fce57a8876a9140a836d8ee19150b965b93a8724e65a79d73100306704f9e50b5bb17576a914de71cb447f326f3a70f9da4a8369ad3068a3493f6888ac " 
		"0100000002355bfc80e5e4d14c634131a30f121a49b27daec201b592d0079247d189dba9a2000000006b483045022100c3ebf9d0a2b44c0a20b84b37bce495f91de3ebd706de9a15cecf77548d2c1a3002203970002c5493b170bd375010b8876799af721a07900c6eb4ee7c21c140469922012103942f6cd9b855c565acd40406a692d39805eef3ab38ec56166afb6d04b071fc21feffffffcb53ff98a0d504249b04c8fe829e9a0c3bd468caeaaba50f3da6d16b0b69eaf3000000006a4730440220138197f27a806028f3bd885aa0e0fecd3b9e2cce43f09d18ed7219e5a087ab0e022075e18b7a8031d340ef2f97fd2efef3a51fbe1b0a2ae04cb76f3ba4ca500e895b01210286921478ed27357ee44f5a5340b051a33b84f5654b7c1d3ec5da2dc9f39d6e3afeffffff02a0850b54020000001976a9142488e2ce9de4952ce739d5cb0df3f2f6bae2395c88ac00e40b540200000017a914babe4713f8e43291e490f738e1b38474440be152872c010000 ")
        );

	//the return data
	UniValue result(UniValue::VOBJ);
	
	LOCK(cs_main);
	RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VSTR));
			
	//check params size
	if (params[0].get_str().size() <= 0||(params[1].get_str().size() <= 0))
		{
			return false;
		}

	//get the contract from parameter 0
	string strContract = params[0].get_str();
	std::vector<unsigned char>vContract = ParseHex(strContract);
	CScript contract(vContract.begin(),vContract.end());

	//split the contract
	std::string contractString	= ScriptToAsmStr(contract);
	std::vector<std::string> vStr;
	boost::split( vStr, contractString, boost::is_any_of( " " ), boost::token_compress_on );

	//contract check
	if(!contract.IsCrossChainPaymentScript())
		{
			return JSONRPCError(RPC_INVALID_PARAMS, "Error:the parameter is no stander contract");
		}

	//get lock time 
	int64_t lockTime = atoi64(vStr[8]);

	//get refund address hash
	std::vector<unsigned char> vRefundAddressHash = ParseHex(vStr[13]);
	uint160 refundAddressHash(vRefundAddressHash);

	//decode the tx
	CTransaction preTx;
	if (!DecodeHexTx(preTx, params[1].get_str()))
		return JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");

	//declare transaction
	CMutableTransaction txNew;
	CAmount nFeePay = 3100;

	//get the redeem amount
	CAmount preOutAmount = 0;
	COutPoint preOutPoint;
	uint256 preTxid = preTx.GetHash();	
	CTxOut preTxOut;
	uint32_t preOutN =0;	
	std::vector<valtype> vSolutions;
	txnouttype addressType = TX_NONSTANDARD;
	uint160 addrhash;

	BOOST_FOREACH(const CTxOut& txout, preTx.vout) 
	{
		const CScript scriptPubkey = StripClaimScriptPrefix(txout.scriptPubKey);
		if (Solver(scriptPubkey, addressType, vSolutions))
		{
			if(addressType== TX_SCRIPTHASH )
			{
				addrhash=uint160(vSolutions[0]);
				preOutAmount =	txout.nValue;
				CTxIn tmptxin = CTxIn(preTxid,preOutN,CScript(),(std::numeric_limits<uint32_t>::max()-1));
				tmptxin.prevPubKey = txout.scriptPubKey;
				txNew.vin.push_back(tmptxin);
				break;					
			}
		}
		preOutN++;
	}

	if(addressType !=TX_SCRIPTHASH)
		{
			throw JSONRPCError(RPC_INVALID_PARAMS, "Error:the transaction have none P2SH type tx out");	
		}	

	//check the contract is match transaction or not 
	if ( 0 != strcmp(addrhash.ToString().c_str(),Hash160(vContract).ToString().c_str()) )
	{
		return JSONRPCError(RPC_INVALID_PARAMS, "Error:the contract in parameter can't match transaction in parameter");
	}	

	//get the pubkey and key of participate address
	const CKeyStore& keystore = *pwalletMain;
	CKeyID keyID(refundAddressHash);
	CPubKey pubKey;
	CKey key;	
	if(!keystore.GetPubKey(keyID,pubKey))
		{
			return JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error:Can't find the pubkey of participte address");			
		}
	if(!keystore.GetKey(keyID,key))
		{
			return JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error:Can't find the key of participte address");	
		}

	//get the out pubkey type p2pkh
	CReserveKey reservekey(pwalletMain);
	CPubKey newKey;
	bool ret;
	ret = reservekey.GetReservedKey(newKey);
	assert(ret);
	CBitcoinAddress outPutAddress(CTxDestination(newKey.GetID()));
	if (!outPutAddress.IsValid())
		return JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Ulord address");

	// Start building the lock script for the p2pkh type.
	CScript refundP2PkHScript = GetScriptForDestination(CTxDestination(newKey.GetID()));
	CAmount nAmount = preOutAmount- nFeePay;
	CTxOut outNew(nAmount,refundP2PkHScript);
	txNew.vout.push_back(outNew);

	txNew.nLockTime = lockTime;
	txNew.nVersion = 1;

	// Sign the refund transaction
	
	CTransaction txNewConst(txNew);
	std::vector<unsigned char> vchSig;
	CScript scriptSigRs;
	uint256 hash = SignatureHash(contract, txNew, 0, SIGHASH_ALL);

    bool signSuccess = key.Sign(hash, vchSig);	
   	bool verifySuccess = pubKey.Verify(hash,vchSig);
	vchSig.push_back((unsigned char)SIGHASH_ALL);	
	if(!verifySuccess)
		{
			return JSONRPCError(RPC_INTERNAL_ERROR, "ERROR:verify the sign of transaction error");
		}

	if(signSuccess)
		{
			CScript script1 =CScript() <<ToByteVector(vchSig);
			CScript script2 =CScript() << ToByteVector(pubKey);
			CScript script4 =CScript() << OP_FALSE <<ToByteVector(vContract);
			scriptSigRs= script1 + script2 + script4;
			txNew.vin[0].scriptSig = scriptSigRs;				
		}
	else
		{
			return JSONRPCError(RPC_INTERNAL_ERROR, "ERROR:sign transaction error");
		}

	//add the sign of transaction
	unsigned int nBytes = ::GetSerializeSize(txNew, SER_NETWORK, PROTOCOL_VERSION);

	// Limit size
	if (nBytes >= MAX_STANDARD_TX_SIZE)
		{
			return JSONRPCError(RPC_INTERNAL_ERROR, "ERROR:transaction too large");
		}

	//Is Dust
	if (txNew.vout[0].IsDust(::minRelayTxFee))
		{
			return JSONRPCError(RPC_INTERNAL_ERROR, "ERROR:transaction is dust transaction");
		}

	//CTransaction txNewend(txNew);
	
	CWalletTx wtxNew;
	wtxNew.fTimeReceivedIsTxTime = true;
	wtxNew.BindWallet(pwalletMain);
	wtxNew.fFromMe = true;
	*static_cast<CTransaction*>(&wtxNew) = CTransaction(txNew);		
	if (!pwalletMain->CommitTransaction(wtxNew, reservekey,NetMsgType::TX))
			return JSONRPCError(RPC_WALLET_ERROR, "Transaction commit failed");

	double fFeePay = (double)nFeePay;
	string strRefundFee = strprintf("Refund fee: %.8f UT(%.8f UT/kB)\n", (fFeePay / COIN), ((fFeePay / COIN)/nBytes));
	result.push_back(Pair("Refund fee",strRefundFee));
	result.push_back(Pair("Refund transaction hash",CTransaction(txNew).GetHash().GetHex()));
	result.push_back(Pair("Refund transaction",EncodeHexTx(CTransaction(txNew))));		

    return result;
}
UniValue crosschainextractsecret(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() !=2)
        throw runtime_error(
		"crosschainextractsecret \"contract transaction \n"
		"\nExtract secret from crosschain redeem transaction (serialized, hex-encoded).\n"
		"\nArguments:\n"
		"1. \redeem transaction \"  (string,required) The contract raw transaction in hex\n"
		"nResult:\n"
		"\"hex\"			 (string) The secret in hex\n"
		"\nExamples:\n"
		"\nextract secret\n"
		+ HelpExampleCli("crosschainextractsecret",
		"010000000199748737a44ab1e988434450704c7434390b662f529d8ef82b7da4061aa84b7d01000000e048304502210088b3a6145b1f5c42538884d7bba539b12b58e87d42f0428ed49198d46a1f7b8402204e595e24f04bf1886ff6ae1092d9a6d5aa9d5cfb8593adf221f5dd46c40341e7012103bd70e22349c72f10adb1e2e27c55fd8d044d99df6aea8a7e87224cad0e943f6120b0316faffb7b0f2b2229347ed6b7bf7b538ff5cbc8d89927862cd2a5c76a7da1514c5163a6140a5070c5c4b93675530823366b35e380ff80eb4c8876a9140a836d8ee19150b965b93a8724e65a79d73100306704d1f70b5bb17576a91466668c2a81e90433bf6cd055c149ca4bb3275ce46888acffffffff01e4d70b54020000001976a9148c9adfee5d9e1ea53e641263b28a1645c2030ade88ac3c010000 ")
        );

	//the return data	
    UniValue result(UniValue::VOBJ);

	LOCK(cs_main);
	RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR));

    //check params size
    if (params[0].get_str().size() <= 0)
		{
			return JSONRPCError(RPC_INVALID_PARAMS, "Error:the parameter size can't be zero");
		}
	
	//decode the tx
	CTransaction redeemTx;
	if (!DecodeHexTx(redeemTx, params[0].get_str()))
       return JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
	CScript scriptSig = redeemTx.vin[0].scriptSig;

	//split the scriptSig
	std::string scriptSigString  = ScriptToAsmStr(scriptSig);
	std::vector<std::string> vStr;
    boost::split( vStr, scriptSigString, boost::is_any_of( " " ), boost::token_compress_on );

	//get contract
	std::vector<unsigned char> vContract = ParseHex(vStr[4]);
	CScript contract(vContract.begin(),vContract.end());

	//contract check
	if(!contract.IsCrossChainPaymentScript())
		{
			return JSONRPCError(RPC_INVALID_PARAMS, "Error:the parameter is no stander contract");
		}
	
	//split the contract
	std::string contractString  = ScriptToAsmStr(contract);
	std::vector<std::string> vStrC;
    boost::split( vStrC, contractString, boost::is_any_of( " " ), boost::token_compress_on );	

	//get secret hash from contract
	std::vector<unsigned char> contractSecretHash = ParseHex(vStrC[2]);	
	uint160 uContractSecretHash(contractSecretHash);

    //get secret form script sig
    std::string secretString =vStr[2];
	std::vector<unsigned char> scriptSigSecretVector =ParseHex(vStr[2]);

	//check the secret in parameter and in contract
	std::vector<unsigned char> transactionSecretHash(20);
	CRIPEMD160().Write(begin_ptr(scriptSigSecretVector), scriptSigSecretVector.size()).Finalize(begin_ptr(transactionSecretHash));
	uint160 uTransactionSecretHash(transactionSecretHash);	
	if ( 0 != strcmp(uContractSecretHash.ToString().c_str(),uTransactionSecretHash.ToString().c_str()) )
		{
			return JSONRPCError(RPC_INVALID_PARAMS, "Error:the secret in parameter not match in in contract");		
		}

	//return the secret
	result.push_back(Pair("secret",secretString));

    return result;


}

char * timetostr(int t,char *buf)
{
	int h = t / 3600;
	int m_t = t - 3600 * h;
	int m = m_t / 60;
	int s = m_t - m * 60;
	sprintf(buf,"%dh %dm %ds",h,m,s);
	return buf;
}
UniValue crosschainauditcontract(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() !=2)
        throw runtime_error(
            "params.size error\n"
        );
	LOCK(cs_main);
    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VSTR));
	// The first parameter is the contract, and the hash160 algorithm is used for it.
	string str_contract = params[0].get_str();
	std::vector<unsigned char>v_contract = ParseHex(str_contract);
	CScript contract(v_contract.begin(),v_contract.end());
	 //contract check
	if(!contract.IsCrossChainPaymentScript())
	{
		return JSONRPCError(RPC_INVALID_PARAMS, "Error:the parameter is no stander contract");
	}
	CScriptID contractP2SH = CScriptID(contract);
	CBitcoinAddress contract_address;
	std::vector<std::string> vStr;

	// The second parameter is the raw data for a transaction.
	// parse hex string from parameter.
	CTransaction tx;
    if (!DecodeHexTx(tx, params[1].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
	
	// The transaction object constructed by the transaction is parsed.
	std::vector<valtype> vSolutions;
	txnouttype addressType;
	uint160 addrhash;
	CAmount value;
	BOOST_FOREACH(const CTxOut& txout, tx.vout) 
	{
		const CScript scriptPubkey = StripClaimScriptPrefix(txout.scriptPubKey);
		if (Solver(scriptPubkey, addressType, vSolutions))
		{
	        if(addressType== TX_SCRIPTHASH )
	        {
	            addrhash=uint160(vSolutions[0]);
				value = txout.nValue;
				break;
	        }
	        else if(addressType==TX_PUBKEYHASH )
	        {
	            addrhash=uint160(vSolutions[0]);
				continue;
	        }
	        else if(addressType== TX_PUBKEY)
	        {
	            addrhash= Hash160(vSolutions[0]);
				continue;
	        }
		}
	}
	
	// compare hash160 value of address
	if ( 0 == strcmp(contractP2SH.ToString().c_str(),addrhash.ToString().c_str()) )
	{
	    LogPrintf("the vout of the tx is ok\n");	
		LogPrintf("contractP2SH  :is %s\n",contractP2SH.ToString());
		LogPrintf("addrhash      :is %s\n",addrhash.ToString());	
		contract_address.Set(contractP2SH);
		if (!contract.IsCrossChainPaymentScript())
		{
			LogPrintf("contract is not an atomic swap script recognized by this tool");
		}
		//split the contract
		std::string contractString  = ScriptToAsmStr(contract);
	    boost::split( vStr, contractString, boost::is_any_of( " " ), boost::token_compress_on );
		LogPrintf("addrhRecipient address      :is %s\n",vStr[6]);
		LogPrintf("Author's refund address     :is %s\n",vStr[13]);
	}
	else
	{
		throw JSONRPCError(RPC_INVALID_PARAMS, "TX decode failed");
	}
	CBitcoinAddress repecit_address;
	CBitcoinAddress refund_address;
	std::vector<unsigned char> u_recepit = ParseHex(vStr[6]);
	std::vector<unsigned char> u_refund = ParseHex(vStr[13]);
	uint160 repecit(u_recepit);
	uint160 refund(u_refund);
	repecit_address.Set((CKeyID&)repecit);
	refund_address.Set((CKeyID&)refund);
	
	std::vector<unsigned char> u_secrethash = ParseHex(vStr[2]);
	uint160 secrethash(u_secrethash);
	
	int64_t i_locktime = atoi64(vStr[8]);

	struct timeval tm;
	gettimeofday(&tm,NULL);
	int64_t current_time = tm.tv_sec;
	int64_t remain_time = i_locktime - current_time  ;
	string str_time;
	char buf[100] = {0};
	timetostr(remain_time,buf);
	str_time = buf;	
    UniValue result(UniValue::VOBJ);
	result.push_back(Pair("contract address:",contract_address.ToString()));
	result.push_back(Pair("contract value:",ValueFromAmount(value)));
	result.push_back(Pair("Recipient address:",repecit_address.ToString()));
	result.push_back(Pair("Author's refund address:",refund_address.ToString()));
	result.push_back(Pair("Secret hash:",secrethash.ToString()));
	result.push_back(Pair("Locktime:",DateTimeStrFormat("%Y-%m-%d %H:%M:%S",i_locktime)));
	result.push_back(Pair("Locktime reached in :",str_time));
    return result;
}

UniValue appcrosschaininitial(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 4)
        throw runtime_error(
		"appcrosschaininitial \"straddr_p\" straddr_r \" amount \" secret_hash"
		"\nCreate appcrosschain transaction txout to local node and network.\n"
		"\nArguments:\n"
		"1. \"straddr_p\"   (string,required) The crosschainaddress to redeem.\n"
		"2. \"straddr_r\"   (string,required) The crosschainaddress to refund.\n"
		"3. \"amount\"      (numeric or string,required) The amount in " + CURRENCY_UNIT + " to send. eg 0.1\n"
		"4. \"secret_hash\" (string,required) The secret_hash to construct contract and transaction.\n"
		"\nResult:\n"
		"\"string\"         (string) The contract_addr in string\n"
		"\"hex\"            (string) The contract in hex\n"
		"\"string\"         (string) The txout in string\n"
		"\nExamples:\n"
		"\nCreate a transaction txout\n"
		+ HelpExampleCli("appcrosschaininitial", "\"uKu1CoxEMkseNHmSougU1hKAW5exSm9EM1\" uQLYvAdqW2wef8pZFeeGy5cAPsAJiKgw2d\" 0.1\" 23CctMcwdTYRWRcAgNndvnn2vqwP")
        );
	//the return data
	UniValue result(UniValue::VOBJ);
	
	LOCK(cs_main);

	// get recipient address and check address is valid or not 
	CBitcoinAddress recipientAddress(params[0].get_str());
	if (!recipientAddress.IsValid())
    	return JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Ulord address");
	uint160 uRecipientAddress = recipientAddress.GetData();

	// get refund address and check address is valid or not
	CBitcoinAddress refundAddress(params[1].get_str());
	if (!refundAddress.IsValid())
    	return JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Ulord address");
	uint160 uRefundAddress = refundAddress.GetData();

	// get amount
    CAmount nAmount = AmountFromValue(params[2]);
    if (nAmount <= 0)
        return JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");

	//get secret form parameter 2
	std::vector<unsigned char>secretHash;
	//std::vector<unsigned char> b58SecretHash = ParseHex(params[3].get_str());
	//string tmpStrSecretHash(b58SecretHash.begin(),b58SecretHash.end());

	string tmpStrSecretHash = params[3].get_str();
	DecodeBase58(tmpStrSecretHash, secretHash);
	LogPrintf("%s",params[3].get_str());

	// Gets the current Unix timestamp.(hex)
	struct timeval tm;
	gettimeofday(&tm,NULL);
    // 172800 is 48hour to second
	int64_t l_time = tm.tv_sec + 172800;
	//l_time = 0x5b10bbb9;

	// construct contract of script
	CScript contract =  CScript() << OP_IF << OP_RIPEMD160 << ToByteVector(secretHash) << OP_EQUALVERIFY << OP_DUP << OP_HASH160 \
	<< ToByteVector(uRecipientAddress) << OP_ELSE << l_time << OP_CHECKLOCKTIMEVERIFY << OP_DROP << OP_DUP << OP_HASH160\
	<< ToByteVector(uRefundAddress) << OP_ENDIF << OP_EQUALVERIFY << OP_CHECKSIG;
	
	// The build script is 160 hashes.
	CScriptID contractP2SH = CScriptID(contract);
	CBitcoinAddress contractAddress;
	contractAddress.Set(contractP2SH);	
	// Start building the lock script for the p2sh type.
	CScript contractP2SHPkScript = GetScriptForDestination(CTxDestination(contractP2SH));

	// build the txout 
	//CTxOut txOut(nAmount,contractP2SHPkScript);
	string txOut = strprintf("CTxOut(nValue=%d.%08d, scriptPubKey=%s)", nAmount / COIN, nAmount % COIN, HexStr(contractP2SHPkScript));
	
	// set the return data
	result.push_back(Pair("contract_addr",contractAddress.ToString()));
	result.push_back(Pair("contract",HexStr(contract.begin(),contract.end())));
	//result.push_back(Pair("txOut ",txOut.ToString()));	
	result.push_back(Pair("txOut",txOut));	
	
	// return data	
    return result;
}

UniValue appcrosschainparticipate(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() !=4)
        throw runtime_error(
		"appcrosschainparticipate \"straddr_p \"straddr_r \"amount \"secret_hash"
		"\nCreate appcrosschain transaction txout to local node and network.\n"
		"\nArguments:\n"
		"1. \"straddr_p\"    (string,required) The crosschainaddress to redeem.\n"
		"2. \"straddr_r\"    (string,required) The crosschainaddress to refund.\n"
		"3. \"amount\"       (numeric or string,required) The amount in " + CURRENCY_UNIT + " to send. eg 0.1\n"
		"4. \"secret_hash \" (string,required) The secret hash. \n"
		"\nResult:\n"
		"\"string\"          (string) The contract_addr in string\n"
		"\"hex\"             (string) The contract in hex\n"
		"\"string\"          (string) The txout in string\n"
		"\nExamples:\n"
		"\nCreate a transaction txout\n"
		+ HelpExampleCli("appcrosschainparticipate", "\"uKu1CoxEMkseNHmSougU1hKAW5exSm9EM1\" uQLYvAdqW2wef8pZFeeGy5cAPsAJiKgw2d\" 0.1\" 23CctMcwdTYRWRcAgNndvnn2vqwP")
        );


	UniValue result(UniValue::VOBJ);
	LOCK(cs_main);

	// get recipient address and check address is valid or not 
	CBitcoinAddress recipientAddress(params[0].get_str());
	if (!recipientAddress.IsValid())
    	return JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Ulord address");
	uint160 uRecipientAddress = recipientAddress.GetData();

	// get refund address and check address is valid or not
	CBitcoinAddress refundAddress(params[1].get_str());
	if (!refundAddress.IsValid())
    	return JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Ulord address");
	uint160 uRefundAddress = refundAddress.GetData();		

	// Amount
    CAmount nAmount = AmountFromValue(params[2]);
    if (nAmount <= 0)
        return JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");

	//get secret form parameter 2
	std::vector<unsigned char>secretHash;
	string tmpStrSecretHash = params[3].get_str();
	DecodeBase58(tmpStrSecretHash, secretHash);

	// Gets the current Unix timestamp.(hex)
	struct timeval tm;
	gettimeofday(&tm,NULL);
    // 86400 is 24hour to second
	int64_t l_time = tm.tv_sec + 86400;
	//l_time = 0x5b10bbb9;
	
	CScript contract =  CScript() << OP_IF << OP_RIPEMD160 << ToByteVector(secretHash) << OP_EQUALVERIFY << OP_DUP << OP_HASH160 \
	<< ToByteVector(uRecipientAddress) << OP_ELSE << l_time << OP_CHECKLOCKTIMEVERIFY << OP_DROP << OP_DUP << OP_HASH160\
	<< ToByteVector(uRefundAddress) << OP_ENDIF << OP_EQUALVERIFY << OP_CHECKSIG;
	
	// The build script is 160 hashes.
	CScriptID contractP2SH = CScriptID(contract);
	CBitcoinAddress contractAddress;
	contractAddress.Set(contractP2SH);	
	// Start building the lock script for the p2sh type.
	CScript contractP2SHPkScript = GetScriptForDestination(CTxDestination(contractP2SH));

	// build the txout 
	//CTxOut txOut(nAmount,contractP2SHPkScript);
	string txOut = strprintf("CTxOut(nValue=%d.%08d, scriptPubKey=%s)", nAmount / COIN, nAmount % COIN, HexStr(contractP2SHPkScript));


	
	// set the return data
	result.push_back(Pair("contract_addr",contractAddress.ToString()));
	result.push_back(Pair("contract",HexStr(contract.begin(),contract.end())));
	//result.push_back(Pair("txOut ",txOut.ToString()));	
	result.push_back(Pair("txOut",txOut));	

    return result;
}

UniValue appcrosschainredeem(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() !=4)
        throw runtime_error(
            "appcrosschainredeem \"contract\" \"scriptsig\" \"pubkey \"secret "
            "\nCreate appcrosschain redeem transaction scriptsig (hex-encoded) to local node and network.\n"
            "\nArguments:\n"
            "1. \"contract \"  (string,required) The contract in hex\n"
            "2. \"scriptsig \" (string,required) The scriptsig in hex\n"
            "3. \"pubkey \"    (string,required) The pubkey in hex\n"
            "3. \"secret \"    (string,required) (string,required) The secret in hex\n"
            "nResult:\n"
            "\"string\"        (string) The scriptsig to redeem transacton\n"
			"\nExamples:\n"
			"\nCreate a redeem transaction scriptsig\n"
            + HelpExampleCli("appcrosschainredeem", "\"63a6144a807c17c36019a0292000e1631c5ba25389ff4a8876a9140a836d8ee19150b965b93a8724e65a79d73100306704b9bb105bb17576a9143b38cd88198165424d71d8e6b51e8ad487c4d0556888ac  \"30440220411f58f7ce0a890501ab5fcb2ac718c207a2e51a249ec2ab795f18046efffd98022008b0c025e653c1ad9cd74cce36f70534c35676b5e81e3da01166e3bb27b9b8e8  \"03bd70e22349c72f10adb1e2e27c55fd8d044d99df6aea8a7e87224cad0e943f61 \"f6eaf6bdd41068a49aa5e8fa201b34cf9d334b2d41c5218b3be4ed0232386bed \"")
        );
	
	//the return data
	UniValue result(UniValue::VOBJ);

	LOCK(cs_main);
	RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VSTR)(UniValue::VSTR)(UniValue::VSTR));

    //check params size
    if ((params[0].get_str().size() <= 0)||(params[1].get_str().size() <= 0)||(params[2].get_str().size() <= 0)||(params[3].get_str().size() <= 0))
		{
			return JSONRPCError(RPC_INVALID_PARAMS, "Error:the parameter size can't be zero");
		}

	//get the contract from parameter 0
	string strContract = params[0].get_str();
	std::vector<unsigned char>vContract = ParseHex(strContract);
	CScript contract(vContract.begin(),vContract.end());

	//split the contract
	std::string contractString  = ScriptToAsmStr(contract);
	std::vector<std::string> vStr;
    boost::split( vStr, contractString, boost::is_any_of( " " ), boost::token_compress_on );

    //contract check
	if(!contract.IsCrossChainPaymentScript())
		{
			return JSONRPCError(RPC_INVALID_PARAMS, "Error:the parameter is no stander contract");
		}	

	//get secret hash from contract
	std::vector<unsigned char> contractSecretHash = ParseHex(vStr[2]);	
	uint160 uContractSecretHash(contractSecretHash);

    //get secret form parameter 2
	std::vector<unsigned char> secretVector =ParseHexV(params[3], "secret");

	//check the secret in parameter and in contract
	std::vector<unsigned char> transactionSecretHash(20);
	CRIPEMD160().Write(begin_ptr(secretVector), secretVector.size()).Finalize(begin_ptr(transactionSecretHash));
	uint160 uTransactionSecretHash(transactionSecretHash);	
	if ( 0 != strcmp(uContractSecretHash.ToString().c_str(),uTransactionSecretHash.ToString().c_str()) )
		{
			return JSONRPCError(RPC_INVALID_PARAMS, "Error:the secret in parameter not match in in contract");		
		}

	//get participent address hash
	std::vector<unsigned char> vParticipentAddressHash = ParseHex(vStr[6]);
	uint160 participentAddressHash(vParticipentAddressHash);

	std::vector<unsigned char> vpubkey = ParseHexV(params[2], "pubkey");
	uint160 pubkeyAddressHash = Hash160(vpubkey);
	if ( 0 != strcmp(participentAddressHash.ToString().c_str(),pubkeyAddressHash.ToString().c_str()) )
		{
			return JSONRPCError(RPC_INVALID_PARAMS, "Error:the pubkey not match participent address in contract");		
		}

	std::vector<unsigned char> vchSig = ParseHexV(params[1], "scriptsig");

	CScript scriptSigRs;
    vchSig.push_back((unsigned char)SIGHASH_ALL);
	

	CScript script1 =CScript() <<ToByteVector(vchSig);
	CScript script2 =CScript() << ToByteVector(vpubkey);
	CScript script3 =CScript() <<ToByteVector(secretVector);
	CScript script4 =CScript() << OP_TRUE <<ToByteVector(vContract);
	scriptSigRs= script1 + script2 + script3 + script4;
	
	string strScriptSigRs = strprintf("%s",HexStr(scriptSigRs));

	result.push_back(Pair("scriptsig",strScriptSigRs));
	return result;
}

UniValue appcrosschainrefund(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() !=3)
        throw runtime_error(
            "appcrosschainrefund \"contract\" \"scriptsig\" \"pubkey \"secret \n"
            "\nCreate appcrosschain refund transaction scriptsig (hex-encoded) to local node and network.\n"
            "\nArguments:\n"
            "1. \"contract \"   (string,required) The contract in hex\n"
            "2. \"scriptsig \"  (string,required) The scriptsig in hex\n"
            "3. \"pubkey \"     (string,required) The pubkey in hex\n"
            "nResult:\n"
            "\"string\"         (string) The scriptsig to refund transacton\n"
			"\nExamples:\n"
			"\nCreate a refund transaction scriptsig\n"
            + HelpExampleCli("appcrosschainrefund", "\"63a6142ac8e36b648a428bc98896d7f9a505ead48b40298876a9140a836d8ee19150b965b93a8724e65a79d73100306704cabb105bb17576a914e186e96ca1c3fc240e6e68b94654e9818c3604346888ac   \"30440220598dab6339ded68855b3eb71110e6229ccb7cb71864d170a508e67c4cb6cd4aa022024caf34ba1feff82aabc4b1dbaff81ad75be7180311045f98002e64396428551   \"02171f146ce3197af5d20f58f5d4af4b081a7ef1e9d3c8a8abc0a1066ba3d9bb23 \"")
        );

	//the return data
	UniValue result(UniValue::VOBJ);

	LOCK(cs_main);
	RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VSTR)(UniValue::VSTR));

    //check params size
    if ((params[0].get_str().size() <= 0)||(params[1].get_str().size() <= 0)||(params[2].get_str().size() <= 0))
		{
			return JSONRPCError(RPC_INVALID_PARAMS, "Error:the parameter size can't be zero");
		}

	//get the contract from parameter 0
	string strContract = params[0].get_str();
	std::vector<unsigned char>vContract = ParseHex(strContract);
	CScript contract(vContract.begin(),vContract.end());

	//split the contract
	std::string contractString  = ScriptToAsmStr(contract);
	std::vector<std::string> vStr;
    boost::split( vStr, contractString, boost::is_any_of( " " ), boost::token_compress_on );

    //contract check
	if(!contract.IsCrossChainPaymentScript())
		{
			return JSONRPCError(RPC_INVALID_PARAMS, "Error:the parameter is no stander contract");
		}	


	//get refund address hash
	std::vector<unsigned char> vRefundAddressHash = ParseHex(vStr[13]);
	uint160 refundAddressHash(vRefundAddressHash);

	std::vector<unsigned char> vpubkey = ParseHexV(params[2], "pubkey");
	uint160 pubkeyAddressHash = Hash160(vpubkey);
	if ( 0 != strcmp(refundAddressHash.ToString().c_str(),pubkeyAddressHash.ToString().c_str()) )
		{
			return JSONRPCError(RPC_INVALID_PARAMS, "Error:the pubkey not match refund address in contract");		
		}

	std::vector<unsigned char> vchSig = ParseHexV(params[1], "scriptsig");

	CScript scriptSigRs;
    vchSig.push_back((unsigned char)SIGHASH_ALL);
	
	CScript script1 =CScript() <<ToByteVector(vchSig);
	CScript script2 =CScript() << ToByteVector(vpubkey);
	CScript script4 =CScript() << OP_FALSE <<ToByteVector(vContract);
	scriptSigRs= script1 + script2 + script4;
	
	string strScriptSigRs = strprintf("%s",HexStr(scriptSigRs));

	result.push_back(Pair("scriptsig",strScriptSigRs));
	return result;

}

UniValue appcrosschainextractsecret(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() !=1)
        throw runtime_error(
		"appcrosschainextractsecret \"rawtransaction \n"
		"\nExtract secret from appcrosschain redeem transaction (serialized, hex-encoded).\n"
		"\nArguments:\n"
		"1.\rawtransaction \"  (string,required) The contract raw transaction in hex\n"
		"nResult:\n"
		"\"hex\"               (string) The secret in hex\n"
		"\nExamples:\n"
		"\nextract secret\n"
		+ HelpExampleCli("appcrosschainextractsecret",
		"01000000010a130c5570ea583c97c363e8ff328a780c311c1dd508e44958ea6b9e9a580b4c01000000df4730440220411f58f7ce0a890501ab5fcb2ac718c207a2e51a249ec2ab795f18046efffd98022008b0c025e653c1ad9cd74cce36f70534c35676b5e81e3da01166e3bb27b9b8e8012103bd70e22349c72f10adb1e2e27c55fd8d044d99df6aea8a7e87224cad0e943f6120f6eaf6bdd41068a49aa5e8fa201b34cf9d334b2d41c5218b3be4ed0232386bed514c5163a6144a807c17c36019a0292000e1631c5ba25389ff4a8876a9140a836d8ee19150b965b93a8724e65a79d73100306704b9bb105bb17576a9143b38cd88198165424d71d8e6b51e8ad487c4d0556888acffffffff01e4d70b54020000001976a9146f9af477ac6f6e1aa67d26bcef71c20855e2f10c88aca6050000 ")
        );
	//the return data	
    UniValue result(UniValue::VOBJ);

	LOCK(cs_main);
	RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR));
	
    //check params size
    if (params[0].get_str().size() <= 0)
		{
			return JSONRPCError(RPC_INVALID_PARAMS, "Error:the parameter size can't be zero");
		}
	
	//decode the tx
	CTransaction redeemTx;
	if (!DecodeHexTx(redeemTx, params[0].get_str()))
       return JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
	CScript scriptSig = redeemTx.vin[0].scriptSig;
	
	//split the scriptSig
	std::string scriptSigString  = ScriptToAsmStr(scriptSig);
	std::vector<std::string> vStr;
    boost::split( vStr, scriptSigString, boost::is_any_of( " " ), boost::token_compress_on );

	//get contract
	std::vector<unsigned char> vContract = ParseHex(vStr[4]);
	CScript contract(vContract.begin(),vContract.end());
	
	//contract check
	if(!contract.IsCrossChainPaymentScript())
		{
			return JSONRPCError(RPC_INVALID_PARAMS, "Error:the parameter is no stander contract");
		}
	
	//split the contract
	std::string contractString  = ScriptToAsmStr(contract);
	std::vector<std::string> vStrC;
    boost::split( vStrC, contractString, boost::is_any_of( " " ), boost::token_compress_on );	
	
	//get secret hash from contract
	std::vector<unsigned char> contractSecretHash = ParseHex(vStrC[2]);	
	uint160 uContractSecretHash(contractSecretHash);

    //get secret form script sig
    std::string secretString =vStr[2];
	std::vector<unsigned char> scriptSigSecretVector =ParseHex(vStr[2]);

	//check the secret in parameter and in contract
	std::vector<unsigned char> transactionSecretHash(20);
	CRIPEMD160().Write(begin_ptr(scriptSigSecretVector), scriptSigSecretVector.size()).Finalize(begin_ptr(transactionSecretHash));
	uint160 uTransactionSecretHash(transactionSecretHash);	
	if ( 0 != strcmp(uContractSecretHash.ToString().c_str(),uTransactionSecretHash.ToString().c_str()) )
		{
			return JSONRPCError(RPC_INVALID_PARAMS, "Error:the secret in parameter not match in in contract");		
		}

	//return the secret
	result.push_back(Pair("secret",secretString));
    return result;


}

UniValue appcrosschainauditcontract(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() !=2)
        throw runtime_error(
        "appcrosschainauditcontract \"contract\" rawtx1\n"
        "\nAudit appcrosschain transactions and crosschain contracts.\n"
        "\nArguments:\n"
        "1. \"contract\"  (string,required) The crosschain contract(hex string) to to send to .\n"
        "2. \"rawtx1 \"   (string,required) The hex string of the raw transaction\n"
        "\nResult:\n"
        "\"string\"       (string) is_contract in string\n"
        "\"amount\"       (amount) tx_value in amount \n"
        "\"string\"       (string) part_addr in string\n"
        "\"string\"       (string) screct_hash in string\n"
        "\"string\"       (string) lock_time in string\n"
        "\nExamples:\n"
        "\naduit the contract\n"
        + HelpExampleCli("appcrosschainauditcontract", "\"63a6144a807c17c36019a0292000e1631c5ba25389ff4a8876a9140a836d8ee19150b965b93a8724e65a79d73100306704b9bb105bb17576a9143b38cd88198165424d71d8e6b51e8ad487c4d0556888ac " "\"0100000002244d79a1ab2a96c83d334927e13827cea01d50dd061267312ec35a89dab11f22000000006a473044022069692f31c4efb3cca9c43712309257752fff2598987474d083cbdde8c0930f6e02201ec4d256b94dfba16505333fabc8fd4839191eec997329e7ea85b444793794ad012103d94b9c0228e38a7dac0c20d03d68fafca8dd815f44a6abf32e622451e54f9a4efeffffff2c5929b77a3cc49adda1672fd803594a27544ef6122a027235beebe85a096c85000000006a473044022002fab97f2be5dea37cd1d4db0deba637346cde5e019deee3e2228fd19ba3ad1102207ee0b869f4f67511b1b1df5f280870917322df177b44d19ddf160136c5ca5bff0121030366e82c8d7a17eccb5ed0b170a862983ae855a3ffb79939269227f1a0ff932dfeffffff02549e474d000000001976a914413a859d58dc1fd6888c502ced862ca1e1726b2288ac00e40b540200000017a91472a36a34582b29e75a6d78a39c962f325fa73e6287a4050000")

        );
	
	//the return data	
    UniValue result(UniValue::VOBJ);

	LOCK(cs_main);
	RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VSTR));
		
    //check params size
    if ((params[0].get_str().size() <= 0)||(params[1].get_str().size() <= 0))
		{
			return JSONRPCError(RPC_INVALID_PARAMS, "Error:the parameter size can't be zero");
		}

	//get the contract from parameter 0
	string strContract = params[0].get_str();
	std::vector<unsigned char>vContract = ParseHex(strContract);
	CScript contract(vContract.begin(),vContract.end());

	//split the contract
	std::string contractString  = ScriptToAsmStr(contract);
	std::vector<std::string> vStr;
    boost::split( vStr, contractString, boost::is_any_of( " " ), boost::token_compress_on );

    //contract check
	if(!contract.IsCrossChainPaymentScript())
		{
			return JSONRPCError(RPC_INVALID_PARAMS, "Error:the parameter is no stander contract");
		}	

	// get recipient address and check address is valid or not 
	CBitcoinAddress recipientAddress;	
	std::vector<unsigned char> uRcepit = ParseHex(vStr[6]);
	uint160 repecit(uRcepit);	
	recipientAddress.Set((CKeyID&)repecit);
	if (!recipientAddress.IsValid())
    	return JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Ulord address");
	
    //decode the tx
	CTransaction preTx;
	if (!DecodeHexTx(preTx, params[1].get_str()))
       return JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");

	//get secret hash from contract
	std::vector<unsigned char> contractSecretHash = ParseHex(vStr[2]);	
	uint160 uContractSecretHash(contractSecretHash);
	// Base58 encoding the secret
    std::string strSecretHash = EncodeBase58(contractSecretHash);

	//declare transaction
	CMutableTransaction txNew;
	
    //get the redeem amount
	CAmount preOutAmount = 0;
	COutPoint preOutPoint;
	uint256 preTxid = preTx.GetHash();
	CTxOut preTxOut;
	uint32_t preOutN =0;	
	std::vector<valtype> vSolutions;
	txnouttype addressType = TX_NONSTANDARD;
	uint160 addrhash;
			
	BOOST_FOREACH(const CTxOut& txout, preTx.vout) 
	{
		const CScript scriptPubkey = StripClaimScriptPrefix(txout.scriptPubKey);
		if (Solver(scriptPubkey, addressType, vSolutions))
		{
	        if(addressType== TX_SCRIPTHASH )
	        {
	            addrhash=uint160(vSolutions[0]);
				preOutAmount =  txout.nValue;
				CTxIn tmptxin = CTxIn(preTxid,preOutN,CScript());
				tmptxin.prevPubKey = txout.scriptPubKey;
				txNew.vin.push_back(tmptxin);
				break;	
	        }
		}
		preOutN++;
	}

	if(addressType !=TX_SCRIPTHASH)
	{
		return JSONRPCError(RPC_INVALID_PARAMS, "Error:the transaction have none P2SH type tx out");	
	}

	//check the contract is match transaction or not 
	if ( 0 != strcmp(addrhash.ToString().c_str(),Hash160(vContract).ToString().c_str()) )
	{
		return JSONRPCError(RPC_INVALID_PARAMS, "Error:the contract in parameter can't match transaction in parameter");
	}

	bool isTrueContract = true;
	double reAmount  = (double)preOutAmount / COIN;


//	int64_t i_locktime = atoi64(vStr[8]);	
	string str_time;
	str_time= vStr[8];

	// set the return data
	result.push_back(Pair("is_contract",isTrueContract));
	result.push_back(Pair("tx_value",reAmount));
	result.push_back(Pair("part_addr",recipientAddress.ToString()));
	result.push_back(Pair("screct_hash",strSecretHash));	
	result.push_back(Pair("lock_time",str_time));
	//result.push_back(Pair("Locktime:",DateTimeStrFormat("%Y-%m-%d %H:%M:%S",i_locktime)));
	
    return result;
}

UniValue lockcoin(const UniValue &params, bool fHelp)
{
	if (fHelp || params.size() !=3)
        throw runtime_error(
            "lockcoinforsometime \"lock address\" \"lock amount\" \"lock time\" \n"
            "\nCreate lock transaction (serialized, hex-encoded) to local node and network.\n"
            "\nArguments:\n"
	    	"1. \"lock address\"  (string,required) The lockaddress to to send to .\n"
            "2. \"lock amount\" (numeric or string,required) The amount in " + CURRENCY_UNIT + " to send. eg 0.1\n"
            "3. \"lock time\" (numeric or string,required) The time is locktime timestamp eg current time start In seconds \n"
            "\nResult:\n"
	    	"\"hex\"             (string) The secret in hex\n"
            "\"hex\"             (string) The secret hash in hex\n"
            "\"hex\"             (string) The contract for address in hex\n"
            "\"hex\"             (string) The contract transaction hash in hex\n"
            "\"hex\"             (string) The contract raw transaction in hex\n"
            "\nExamples:\n"
            "\nCreate a transaction\n"
            + HelpExampleCli("lockcoin", "\"XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg\" \"0.1\" \"86400\" ") 
        );
        //lockcoin rpc interface base on hash time lock contract
	// parse parameters
	if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;
	LOCK2(cs_main, pwalletMain->cs_wallet);
	CBitcoinAddress address(params[0].get_str());
	if (!address.IsValid())
    	throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Ulord address");

	// Amount
    CAmount nAmount = AmountFromValue(params[1]);
    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");

	// a random value is generated and sha256 hash algorithm is used.
	unsigned char vch[32];
	memset(vch, 0x00, sizeof(vch));
	RandAddSeedPerfmon();
    GetRandBytes(vch, sizeof(vch));
	uint256 secret = Hash(vch,vch+sizeof(vch));
	std::string tem = secret.GetHex();
	std::vector<unsigned char>str_hash(tem.begin(),tem.end());
	
	uint160 secret_hash = Hash160(str_hash);
	std::string hash_tem = secret_hash.GetHex();
  	CBitcoinAddress hash_address;
	hash_address.Set((CScriptID&)secret_hash);

	// Gets the current Unix timestamp.(hex)
	struct timeval tm;
	gettimeofday(&tm,NULL);
    
	int64_t l_time = tm.tv_sec + atoi(params[2].get_str());
	// construct contract of script
	CPubKey newKey;
    if ( !pwalletMain->GetKeyFromPool(newKey) )
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT,"Error: Keypool ran out,please call keypoolrefill first");
	 uint160 refund =  newKey.gethash();
	uint160 addr = address.GetData();

	CScript contract =  CScript() << OP_IF << OP_RIPEMD160 << ToByteVector(secret_hash) << OP_EQUALVERIFY << OP_DUP << OP_HASH160 \
	<< ToByteVector(addr) << OP_ELSE << l_time << OP_CHECKLOCKTIMEVERIFY << OP_DROP << OP_DUP << OP_HASH160\
	<< ToByteVector(refund) << OP_ENDIF << OP_EQUALVERIFY << OP_CHECKSIG;
	
	// The build script is 160 hashes.
	CScriptID contractP2SH = CScriptID(contract);
	CBitcoinAddress contract_address;
	contract_address.Set(contractP2SH);	
	// Start building the lock script for the p2sh type.
	CScript contractP2SHPkScript = GetScriptForDestination(CTxDestination(contractP2SH));

	// The amount is locked in the redemption script.
	 vector<CRecipient> vecSend;
    int nChangePosRet = -1;
    CRecipient recipient = {contractP2SHPkScript,nAmount,false};
    vecSend.push_back(recipient);

	// Start building a deal
	CReserveKey reservekey(pwalletMain);
	CAmount nFeeRequired = 0;
    std::string strError;
	CWalletTx wtxNew;
	if ( !pwalletMain->CreateTransaction(vecSend,wtxNew,reservekey,nFeeRequired,nChangePosRet,strError))
		{
			if ( nAmount + nFeeRequired > pwalletMain->GetBalance() )
			{
				strError = strprintf("Error: This transaction requires a transaction fee of at leasst %s because if its amount, complex, or use of recently received funds!",FormatMoney(nFeeRequired));
			}
			LogPrintf("%s() : %s\n",__func__,strError);
			throw JSONRPCError(RPC_WALLET_ERROR,strError);
		}
			
		if ( !pwalletMain->CommitTransaction(wtxNew,reservekey) )
			throw JSONRPCError(RPC_WALLET_ERROR,"Error: The transaction was rejected! This might hapen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
	
	UniValue result(UniValue::VOBJ);
	CBitcoinAddress refund_address;
	refund_address.Set(CKeyID(refund));
	result.push_back(Pair("refund_address",refund_address.ToString()));
	result.push_back(Pair("hexstring",wtxNew.GetHash().GetHex()));
	result.push_back(Pair("hex",EncodeHexTx(wtxNew)));
	result.push_back(Pair("Contract(address) ",contract_address.ToString()));
	result.push_back(Pair("contract",HexStr(contract.begin(),contract.end())));
	result.push_back(Pair("secret",secret.ToString()));
	result.push_back(Pair("secrethash",secret_hash.ToString()));
    return result;
}

UniValue unlockcoin(const UniValue &params, bool fHelp)
{
	 if (fHelp || params.size() !=2)
        throw runtime_error(
		"refundlockcoin \"contract \" \"contract transaction\" \n"
		"\nCreate lockcoin refund transaction (serialized, hex-encoded) to local node and network.\n"
		"\nArguments:\n"
		"1. \"contract \"  (string,required) The contract in hex\n"
		"2. \"contract transaction \"  (string,required) The contract raw transaction in hex\n"
		"nResult:\n"
		"\"Refund fee\" 	 (string) The refund fee of redeem transacton\n"
		"\"hex\"			 (string) The refund transaction hash in hex\n"
		"\"hex\"			 (string) The refund raw transaction in hex\n"
		"\nExamples:\n"
		"\nCreate a refund transaction\n"
		+ HelpExampleCli("unlockcoin", "63a6148887e0860cc6d28972b4622e9f2e1c2bc4fce57a8876a9140a836d8ee19150b965b93a8724e65a79d73100306704f9e50b5bb17576a914de71cb447f326f3a70f9da4a8369ad3068a3493f6888ac " 
		"0100000002355bfc80e5e4d14c634131a30f121a49b27daec201b592d0079247d189dba9a2000000006b483045022100c3ebf9d0a2b44c0a20b84b37bce495f91de3ebd706de9a15cecf77548d2c1a3002203970002c5493b170bd375010b8876799af721a07900c6eb4ee7c21c140469922012103942f6cd9b855c565acd40406a692d39805eef3ab38ec56166afb6d04b071fc21feffffffcb53ff98a0d504249b04c8fe829e9a0c3bd468caeaaba50f3da6d16b0b69eaf3000000006a4730440220138197f27a806028f3bd885aa0e0fecd3b9e2cce43f09d18ed7219e5a087ab0e022075e18b7a8031d340ef2f97fd2efef3a51fbe1b0a2ae04cb76f3ba4ca500e895b01210286921478ed27357ee44f5a5340b051a33b84f5654b7c1d3ec5da2dc9f39d6e3afeffffff02a0850b54020000001976a9142488e2ce9de4952ce739d5cb0df3f2f6bae2395c88ac00e40b540200000017a914babe4713f8e43291e490f738e1b38474440be152872c010000 ")
        );
        //unlockcoin rpc interface base on hash time lock contract
	//the return data
	UniValue result(UniValue::VOBJ);
	
	LOCK(cs_main);
	RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VSTR));
			
	//check params size
	if (params[0].get_str().size() <= 0||(params[1].get_str().size() <= 0))
		{
			return false;
		}

	//get the contract from parameter 0
	string strContract = params[0].get_str();
	std::vector<unsigned char>vContract = ParseHex(strContract);
	CScript contract(vContract.begin(),vContract.end());

	//split the contract
	std::string contractString	= ScriptToAsmStr(contract);
	std::vector<std::string> vStr;
	boost::split( vStr, contractString, boost::is_any_of( " " ), boost::token_compress_on );

	//contract check
	if(!contract.IsCrossChainPaymentScript())
		{
			return JSONRPCError(RPC_INVALID_PARAMS, "Error:the parameter is no stander contract");
		}

	//get lock time 
	int64_t lockTime = atoi64(vStr[8]);

	//get refund address hash
	std::vector<unsigned char> vRefundAddressHash = ParseHex(vStr[13]);
	uint160 refundAddressHash(vRefundAddressHash);

	//decode the tx
	CTransaction preTx;
	if (!DecodeHexTx(preTx, params[1].get_str()))
		return JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");

	//declare transaction
	CMutableTransaction txNew;
	CAmount nFeePay = 3100;

	//get the redeem amount
	CAmount preOutAmount = 0;
	COutPoint preOutPoint;
	uint256 preTxid = preTx.GetHash();	
	CTxOut preTxOut;
	uint32_t preOutN =0;	
	std::vector<valtype> vSolutions;
	txnouttype addressType = TX_NONSTANDARD;
	uint160 addrhash;

	BOOST_FOREACH(const CTxOut& txout, preTx.vout) 
	{
		const CScript scriptPubkey = StripClaimScriptPrefix(txout.scriptPubKey);
		if (Solver(scriptPubkey, addressType, vSolutions))
		{
			if(addressType== TX_SCRIPTHASH )
			{
				addrhash=uint160(vSolutions[0]);
				preOutAmount =	txout.nValue;
				CTxIn tmptxin = CTxIn(preTxid,preOutN,CScript(),(std::numeric_limits<uint32_t>::max()-1));
				tmptxin.prevPubKey = txout.scriptPubKey;
				txNew.vin.push_back(tmptxin);
				break;					
			}
		}
		preOutN++;
	}

	if(addressType !=TX_SCRIPTHASH)
		{
			throw JSONRPCError(RPC_INVALID_PARAMS, "Error:the transaction have none P2SH type tx out");	
		}	

	//check the contract is match transaction or not 
	if ( 0 != strcmp(addrhash.ToString().c_str(),Hash160(vContract).ToString().c_str()) )
	{
		return JSONRPCError(RPC_INVALID_PARAMS, "Error:the contract in parameter can't match transaction in parameter");
	}	

	//get the pubkey and key of participate address
	const CKeyStore& keystore = *pwalletMain;
	CKeyID keyID(refundAddressHash);
	CPubKey pubKey;
	CKey key;	
	if(!keystore.GetPubKey(keyID,pubKey))
		{
			return JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error:Can't find the pubkey of participte address");			
		}
	if(!keystore.GetKey(keyID,key))
		{
			return JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error:Can't find the key of participte address");	
		}

	//get the out pubkey type p2pkh
	CReserveKey reservekey(pwalletMain);
	CPubKey newKey;
	bool ret;
	ret = reservekey.GetReservedKey(newKey);
	assert(ret);
	CBitcoinAddress outPutAddress(CTxDestination(newKey.GetID()));
	if (!outPutAddress.IsValid())
		return JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Ulord address");

	// Start building the lock script for the p2pkh type.
	CScript refundP2PkHScript = GetScriptForDestination(CTxDestination(newKey.GetID()));
	CAmount nAmount = preOutAmount- nFeePay;
	CTxOut outNew(nAmount,refundP2PkHScript);
	txNew.vout.push_back(outNew);

	txNew.nLockTime = lockTime;
	txNew.nVersion = 1;

	// Sign the refund transaction
	
	CTransaction txNewConst(txNew);
	std::vector<unsigned char> vchSig;
	CScript scriptSigRs;
	uint256 hash = SignatureHash(contract, txNew, 0, SIGHASH_ALL);

    bool signSuccess = key.Sign(hash, vchSig);	
   	bool verifySuccess = pubKey.Verify(hash,vchSig);
	vchSig.push_back((unsigned char)SIGHASH_ALL);	
	if(!verifySuccess)
		{
			return JSONRPCError(RPC_INTERNAL_ERROR, "ERROR:verify the sign of transaction error");
		}

	if(signSuccess)
		{
			CScript script1 =CScript() <<ToByteVector(vchSig);
			CScript script2 =CScript() << ToByteVector(pubKey);
			CScript script4 =CScript() << OP_FALSE <<ToByteVector(vContract);
			scriptSigRs= script1 + script2 + script4;
			txNew.vin[0].scriptSig = scriptSigRs;				
		}
	else
		{
			return JSONRPCError(RPC_INTERNAL_ERROR, "ERROR:sign transaction error");
		}

	//add the sign of transaction
	unsigned int nBytes = ::GetSerializeSize(txNew, SER_NETWORK, PROTOCOL_VERSION);

	// Limit size
	if (nBytes >= MAX_STANDARD_TX_SIZE)
		{
			return JSONRPCError(RPC_INTERNAL_ERROR, "ERROR:transaction too large");
		}

	//Is Dust
	if (txNew.vout[0].IsDust(::minRelayTxFee))
		{
			return JSONRPCError(RPC_INTERNAL_ERROR, "ERROR:transaction is dust transaction");
		}

	//CTransaction txNewend(txNew);
	
	CWalletTx wtxNew;
	wtxNew.fTimeReceivedIsTxTime = true;
	wtxNew.BindWallet(pwalletMain);
	wtxNew.fFromMe = true;
	*static_cast<CTransaction*>(&wtxNew) = CTransaction(txNew);		
	if (!pwalletMain->CommitTransaction(wtxNew, reservekey,NetMsgType::TX))
			return JSONRPCError(RPC_WALLET_ERROR, "Transaction commit failed");

	double fFeePay = (double)nFeePay;
	string strRefundFee = strprintf("Refund fee: %.8f UT(%.8f UT/kB)\n", (fFeePay / COIN), ((fFeePay / COIN)/nBytes));
	result.push_back(Pair("Refund fee",strRefundFee));
	result.push_back(Pair("Refund transaction hash",CTransaction(txNew).GetHash().GetHex()));
	result.push_back(Pair("Refund transaction",EncodeHexTx(CTransaction(txNew))));		

    return result;
}
#endif
