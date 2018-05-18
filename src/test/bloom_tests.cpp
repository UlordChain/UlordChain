// Copyright (c) 2012-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bloom.h"

#include "base58.h"
#include "clientversion.h"
#include "key.h"
#include "merkleblock.h"
#include "random.h"
#include "serialize.h"
#include "streams.h"
#include "uint256.h"
#include "util.h"
#include "utilstrencodings.h"
#include "test/test_ulord.h"

#include <vector>

#include <boost/test/unit_test.hpp>
#include <boost/tuple/tuple.hpp>

using namespace std;
void showbuf(CDataStream& buf)
{
	unsigned int i = 0, count = 0;
	for (i = 0; i < buf.size(); ++i)
	{
		printf("%02x ",(uint8_t)buf[i]);
		count++;
		if(count % 8 == 0)
			printf("    ");
		if(count % 16 == 0)
			printf("\n");
	}
	printf("\n");
}

BOOST_FIXTURE_TEST_SUITE(bloom_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bloom_create_insert_serialize)
{
    CBloomFilter filter(3, 0.01, 0, BLOOM_UPDATE_ALL);

    filter.insert(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8"));
    BOOST_CHECK_MESSAGE( filter.contains(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8")), "BloomFilter doesn't contain just-inserted object!");
    // One bit different in first byte
    BOOST_CHECK_MESSAGE(!filter.contains(ParseHex("19108ad8ed9bb6274d3980bab5a85c048f0950c8")), "BloomFilter contains something it shouldn't!");

    filter.insert(ParseHex("b5a2c786d9ef4658287ced5914b37a1b4aa32eee"));
    BOOST_CHECK_MESSAGE(filter.contains(ParseHex("b5a2c786d9ef4658287ced5914b37a1b4aa32eee")), "BloomFilter doesn't contain just-inserted object (2)!");

    filter.insert(ParseHex("b9300670b4c5366e95b2699e8b18bc75e5f729c5"));
    BOOST_CHECK_MESSAGE(filter.contains(ParseHex("b9300670b4c5366e95b2699e8b18bc75e5f729c5")), "BloomFilter doesn't contain just-inserted object (3)!");

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    filter.Serialize(stream, SER_NETWORK, PROTOCOL_VERSION);

    vector<unsigned char> vch = ParseHex("03614e9b050000000000000001");
    vector<char> expected(vch.size());

    for (unsigned int i = 0; i < vch.size(); i++)
        expected[i] = (char)vch[i];

    BOOST_CHECK_EQUAL_COLLECTIONS(stream.begin(), stream.end(), expected.begin(), expected.end());

    BOOST_CHECK_MESSAGE( filter.contains(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8")), "BloomFilter doesn't contain just-inserted object!");
    filter.clear();
    BOOST_CHECK_MESSAGE( !filter.contains(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8")), "BloomFilter should be empty!");
}

BOOST_AUTO_TEST_CASE(bloom_create_insert_serialize_with_tweak)
{
    // Same test as bloom_create_insert_serialize, but we add a nTweak of 100
    CBloomFilter filter(3, 0.01, 2147483649UL, BLOOM_UPDATE_ALL);

    filter.insert(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8"));
    BOOST_CHECK_MESSAGE( filter.contains(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8")), "BloomFilter doesn't contain just-inserted object!");
    // One bit different in first byte
    BOOST_CHECK_MESSAGE(!filter.contains(ParseHex("19108ad8ed9bb6274d3980bab5a85c048f0950c8")), "BloomFilter contains something it shouldn't!");

    filter.insert(ParseHex("b5a2c786d9ef4658287ced5914b37a1b4aa32eee"));
    BOOST_CHECK_MESSAGE(filter.contains(ParseHex("b5a2c786d9ef4658287ced5914b37a1b4aa32eee")), "BloomFilter doesn't contain just-inserted object (2)!");

    filter.insert(ParseHex("b9300670b4c5366e95b2699e8b18bc75e5f729c5"));
    BOOST_CHECK_MESSAGE(filter.contains(ParseHex("b9300670b4c5366e95b2699e8b18bc75e5f729c5")), "BloomFilter doesn't contain just-inserted object (3)!");

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    filter.Serialize(stream, SER_NETWORK, PROTOCOL_VERSION);

    vector<unsigned char> vch = ParseHex("03ce4299050000000100008001");
    vector<char> expected(vch.size());

    for (unsigned int i = 0; i < vch.size(); i++)
        expected[i] = (char)vch[i];

    BOOST_CHECK_EQUAL_COLLECTIONS(stream.begin(), stream.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(bloom_create_insert_key)
{
    string strSecret = string("cNU9ZAikd1fjVM5ALpsbq7zjn4BFcT9LebkpYR8Am8RJ7FAr1SeZ");
    CBitcoinSecret vchSecret;
    BOOST_CHECK(vchSecret.SetString(strSecret));

    CKey key = vchSecret.GetKey();
    CPubKey pubkey = key.GetPubKey();
    vector<unsigned char> vchPubKey(pubkey.begin(), pubkey.end());

    CBloomFilter filter(2, 0.001, 0, BLOOM_UPDATE_ALL);
    filter.insert(vchPubKey);
    uint160 hash = pubkey.GetID();
    filter.insert(vector<unsigned char>(hash.begin(), hash.end()));

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    filter.Serialize(stream, SER_NETWORK, PROTOCOL_VERSION);

    vector<unsigned char> vch = ParseHex("03d32b99080000000000000001");
	//showbuf(stream);
	//cout << endl;
    vector<char> expected(vch.size());

    for (unsigned int i = 0; i < vch.size(); i++)
        expected[i] = (char)vch[i];

    BOOST_CHECK_EQUAL_COLLECTIONS(stream.begin(), stream.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(bloom_match)
{
    // Random real transaction (b4749f017444b051c44dfd2720e88f314ff94f3dd6d56d40ef65854fcd7fff6b)
    CTransaction tx;
    CDataStream stream(ParseHex("01000000010b26e9b7735eb6aabdf358bab62f9816a21ba9ebdb719d5299e88607d722c190000000008b4830450220070aca44506c5cef3a16ed519d7c3c39f8aab192c4e1c90d065f37b8a4af6141022100a8e160b856c2d43d27d8fba71e5aef6405b8643ac4cb7cb3c462aced7f14711a0141046d11fee51b0e60666d5049a9101a72741df480b96ee26488a4d3466b95c9a40ac5eeef87e10a5cd336c19a84565f80fa6c547957b7700ff4dfbdefe76036c339ffffffff021bff3d11000000001976a91404943fdd508053c75000106d3bc6e2754dbcff1988ac2f15de00000000001976a914a266436d2965547608b9e15d9032a7b9d64fa43188ac00000000"), SER_DISK, CLIENT_VERSION);
    stream >> tx;

    // and one which spends it (e2769b09e784f32f62ef849763d4f45b98e07ba658647343b915ff832b110436)
    unsigned char ch[] = {0x01, 0x00, 0x00, 0x00, 0x01, 0x6b, 0xff, 0x7f, 0xcd, 0x4f, 0x85, 0x65, 0xef, 0x40, 0x6d, 0xd5, 0xd6, 0x3d, 0x4f, 0xf9, 0x4f, 0x31, 0x8f, 0xe8, 0x20, 0x27, 0xfd, 0x4d, 0xc4, 0x51, 0xb0, 0x44, 0x74, 0x01, 0x9f, 0x74, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x8c, 0x49, 0x30, 0x46, 0x02, 0x21, 0x00, 0xda, 0x0d, 0xc6, 0xae, 0xce, 0xfe, 0x1e, 0x06, 0xef, 0xdf, 0x05, 0x77, 0x37, 0x57, 0xde, 0xb1, 0x68, 0x82, 0x09, 0x30, 0xe3, 0xb0, 0xd0, 0x3f, 0x46, 0xf5, 0xfc, 0xf1, 0x50, 0xbf, 0x99, 0x0c, 0x02, 0x21, 0x00, 0xd2, 0x5b, 0x5c, 0x87, 0x04, 0x00, 0x76, 0xe4, 0xf2, 0x53, 0xf8, 0x26, 0x2e, 0x76, 0x3e, 0x2d, 0xd5, 0x1e, 0x7f, 0xf0, 0xbe, 0x15, 0x77, 0x27, 0xc4, 0xbc, 0x42, 0x80, 0x7f, 0x17, 0xbd, 0x39, 0x01, 0x41, 0x04, 0xe6, 0xc2, 0x6e, 0xf6, 0x7d, 0xc6, 0x10, 0xd2, 0xcd, 0x19, 0x24, 0x84, 0x78, 0x9a, 0x6c, 0xf9, 0xae, 0xa9, 0x93, 0x0b, 0x94, 0x4b, 0x7e, 0x2d, 0xb5, 0x34, 0x2b, 0x9d, 0x9e, 0x5b, 0x9f, 0xf7, 0x9a, 0xff, 0x9a, 0x2e, 0xe1, 0x97, 0x8d, 0xd7, 0xfd, 0x01, 0xdf, 0xc5, 0x22, 0xee, 0x02, 0x28, 0x3d, 0x3b, 0x06, 0xa9, 0xd0, 0x3a, 0xcf, 0x80, 0x96, 0x96, 0x8d, 0x7d, 0xbb, 0x0f, 0x91, 0x78, 0xff, 0xff, 0xff, 0xff, 0x02, 0x8b, 0xa7, 0x94, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x19, 0x76, 0xa9, 0x14, 0xba, 0xde, 0xec, 0xfd, 0xef, 0x05, 0x07, 0x24, 0x7f, 0xc8, 0xf7, 0x42, 0x41, 0xd7, 0x3b, 0xc0, 0x39, 0x97, 0x2d, 0x7b, 0x88, 0xac, 0x40, 0x94, 0xa8, 0x02, 0x00, 0x00, 0x00, 0x00, 0x19, 0x76, 0xa9, 0x14, 0xc1, 0x09, 0x32, 0x48, 0x3f, 0xec, 0x93, 0xed, 0x51, 0xf5, 0xfe, 0x95, 0xe7, 0x25, 0x59, 0xf2, 0xcc, 0x70, 0x43, 0xf9, 0x88, 0xac, 0x00, 0x00, 0x00, 0x00, 0x00};
    vector<unsigned char> vch(ch, ch + sizeof(ch) -1);
    CDataStream spendStream(vch, SER_DISK, CLIENT_VERSION);
    CTransaction spendingTx;
    spendStream >> spendingTx;

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(uint256S("0xb4749f017444b051c44dfd2720e88f314ff94f3dd6d56d40ef65854fcd7fff6b"));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match tx hash");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    // byte-reversed tx hash
    filter.insert(ParseHex("6bff7fcd4f8565ef406dd5d63d4ff94f318fe82027fd4dc451b04474019f74b4"));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match manually serialized tx hash");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(ParseHex("30450220070aca44506c5cef3a16ed519d7c3c39f8aab192c4e1c90d065f37b8a4af6141022100a8e160b856c2d43d27d8fba71e5aef6405b8643ac4cb7cb3c462aced7f14711a01"));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match input signature");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(ParseHex("046d11fee51b0e60666d5049a9101a72741df480b96ee26488a4d3466b95c9a40ac5eeef87e10a5cd336c19a84565f80fa6c547957b7700ff4dfbdefe76036c339"));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match input pub key");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(ParseHex("04943fdd508053c75000106d3bc6e2754dbcff19"));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match output address");
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(spendingTx), "Simple Bloom filter didn't add output");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(ParseHex("a266436d2965547608b9e15d9032a7b9d64fa431"));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match output address");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(COutPoint(uint256S("0x90c122d70786e899529d71dbeba91ba216982fb6ba58f3bdaab65e73b7e9260b"), 0));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match COutPoint");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    COutPoint prevOutPoint(uint256S("0x90c122d70786e899529d71dbeba91ba216982fb6ba58f3bdaab65e73b7e9260b"), 0);
    {
        vector<unsigned char> data(32 + sizeof(unsigned int));
        memcpy(&data[0], prevOutPoint.hash.begin(), 32);
        memcpy(&data[32], &prevOutPoint.n, sizeof(unsigned int));
        filter.insert(data);
    }
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match manually serialized COutPoint");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(uint256S("00000009e784f32f62ef849763d4f45b98e07ba658647343b915ff832b110436"));
    BOOST_CHECK_MESSAGE(!filter.IsRelevantAndUpdate(tx), "Simple Bloom filter matched random tx hash");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(ParseHex("0000006d2965547608b9e15d9032a7b9d64fa431"));
    BOOST_CHECK_MESSAGE(!filter.IsRelevantAndUpdate(tx), "Simple Bloom filter matched random address");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(COutPoint(uint256S("0x90c122d70786e899529d71dbeba91ba216982fb6ba58f3bdaab65e73b7e9260b"), 1));
    BOOST_CHECK_MESSAGE(!filter.IsRelevantAndUpdate(tx), "Simple Bloom filter matched COutPoint for an output we didn't care about");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(COutPoint(uint256S("0x000000d70786e899529d71dbeba91ba216982fb6ba58f3bdaab65e73b7e9260b"), 0));
    BOOST_CHECK_MESSAGE(!filter.IsRelevantAndUpdate(tx), "Simple Bloom filter matched COutPoint for an output we didn't care about");
}

BOOST_AUTO_TEST_CASE(merkle_block_1)
{
    // Random real block (00000a890e87bf1b20a03763d1d6dfee6eb3fc33d9441aef68f5ba94f0b50336)
    // With 3 txes
    CBlock block;
    CDataStream stream(ParseHex("000000208d2f3c7d6d678bf9d1632775dfc9b1d7f0f25529cfc6af6c9329a70cfc1c0000e5bc815e556220563ca64e4ef3f96682a85326ee1f24ef933100d9a2da0fe9e9212c0edb2ed53a9af02dc480cd2902732135433324a891e9c42a065ab939d950d9a0b25a91b41f1e4803913b2f48edc44977784e8a36eb9b6bbc0aa5dccfe8e5ef80fdc1a3ef00000301000000010000000000000000000000000000000000000000000000000000000000000000ffffffff050283230103ffffffff0108aa54a1020000002321032aea900bd8b2707e29d6c215e76da08ab40a57b164ac32b5b471d31063bf4602ac00000000010000000213f7361d0fdd0e33e86e2d250afe2bd4d79242f21bba0c8aef3dc6bf0d2a386b000000006a47304402201c1a1d40a922b3460a380865b51ed7b4ab21832e0d8a55f8cf05029b75b7f6a7022059e65582232c4f8cfe7ece96baeb45e630377a0fc8922440facbbbeee262c4840121038fff1f19effa8a5be05e8a0eeea3b214f36836d426a50ea14b1dbb09865aa8edfeffffffc04c4d9628cc58922612fb57af49cdccfa95ce77a21b8f52eec810349afaddbf000000006b483045022100ab4806a1934467cb8f6eaf241aab186f4c57c4ef62bc269e9f752cc63acdbcd8022079bb331877172c5440a8e1e6be43af35d99f10be0f5a9dbbfac25a93337436ea012102d8408529ab6d82c822ebf20e5ad101922b4462a8a53e063a1f5297ba50cc7ccefeffffff02f7496800000000001976a914ad4a1e0eda0e397f2446011f6625cb5b7200a33d88ac36d1989a020000001976a914515ad08de68502a7376f5b61a6b4ee3e87a2388488ac82230000010000000258c3ac35c681da46248148e9525c35c47334aa73121bc842ea1c6c32e33d27f8000000006a4730440220540b6778fa2a5701b721d9d673126ab1807d0d52ef7eb9a572aa7a826099396102205dcdb3a50436e4a940efe0786763fd2b4eeac0ba11f5ce1943db5637c108d89f012103d1570a62462cb6c8f74e4e750ec5176be9335e249943387ac80a9b664e48fee8feffffffa67ec4bbeaaa166eedb75adb484032708edc66ccd1324b9529f3136f948149e3000000006a47304402206c7cc4730620dcae31eab5dcfa64074d5b83316f6cab7e7619ef0e2d06728bb302202dabf8a1d4f4b391c10a2eadad29fe6554571416eec22f36858afc14c5de02c8012102d8408529ab6d82c822ebf20e5ad101922b4462a8a53e063a1f5297ba50cc7ccefeffffff029d560f00000000001976a9145c217c7f73555e830159390a6d291fa925f59bc588ac5cb4989a020000001976a914515ad08de68502a7376f5b61a6b4ee3e87a2388488ac82230000"),SER_NETWORK, PROTOCOL_VERSION);
    stream >> block;

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    // Match the last transaction
    filter.insert(uint256S("0x2b20079614e39eeffc856e2c06ed6abb7dc5bd4e3ea2235ae494b5efe92dff30"));

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 1);
    pair<unsigned int, uint256> pair = merkleBlock.vMatchedTxn[0];

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == uint256S("0x2b20079614e39eeffc856e2c06ed6abb7dc5bd4e3ea2235ae494b5efe92dff30"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 2);

    vector<uint256> vMatched;
    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);

    // Also match the 8th transaction
    filter.insert(uint256S("0x9286f154605d2380b0e0f38dd3a0d32eb4755631315b29110691e8bdeaa870e4"));
    merkleBlock = CMerkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());
	
    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 2);

    BOOST_CHECK(merkleBlock.vMatchedTxn[1] == pair);
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == uint256S("0x9286f154605d2380b0e0f38dd3a0d32eb4755631315b29110691e8bdeaa870e4"));

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 0);

    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);
}

BOOST_AUTO_TEST_CASE(merkle_block_2)
{
    // Random real block (00000981af837857722e4b116a339cbf9fc094f795476a78ca195ba45a3d4882)
    // With 4 txes
    CBlock block;
    CDataStream stream(ParseHex("00000020b2321b0dffadb87480dc8fdaf8f2adcc035cfc1173ceabf30c1d7abd4e0600002d56e9f7a0dececde6a6adb303aa63072fd86e9182ed57bd6a32d058d2295b490100000000000000000000000000000000000000000000000000000000000000e7de9e5ae91a101e120200407e99a328126f9ae0617cbcc0edb1d55fbe959a94265395b4e12649210301000000010000000000000000000000000000000000000000000000000000000000000000ffffffff1602160204e7de9e5a0d2f5374726174756d506f6f6c2f00000000022a44999a020000001976a914da84c6aa28fb77358741e62e6d743e99604c8a5688acdebabb06000000001976a914da84c6aa28fb77358741e62e6d743e99604c8a5688ac000000000100000003822c03d57f61b05110b54b578682ae7805528bf2cd063ad693c48c63619db6fd000000006b48304502210090a416bd51b2db3ff156c9484e516cb9022593fa5b262efd5451ce3319cd3bf4022003c112390baf3d05e31c8f1d8825e16537b5d48a3431e016df2f80b42cd5b258012102f49998de3177c380b46123133f7cdcd4ef89760111cb39b7f9fffd4d710a7764feffffffcecb99c4a951ea5bdd9b88b5c25fc95298ca0a52cb2f85b104f7207074e1d82f000000006a4730440220247214bd1646d1d0cf5379e27c02277ac9bfd28119c7bb4b2f17befb92c0142c0220340f40236d7981fdd61bf413ab35fe6cf3b4dd1907804f0858746699cd890d7301210349836aed9ccfc8794fcc9fd89e409ba4c103d11fd825980c387b290971dad2f7feffffffef43f5c22f075224078907394e6ad8efb5b4348bb112b649b0703b306770829c000000006a47304402206c91a220f46bef22872b6dc2aa5a91a010ca2023f411f800b9857578383563290220228f9de171de8e440756eb3363ec0776aad6df421f78c0a38aabcb1c5c93521d012102333ac4b9b36d923bc018f229b2a364761b22720d606124df8295c1c6c77beef2feffffff10e6480f00000000001976a9146aa8633c695ee4b0b1b0c7da50e4a9bb5f63675788ac1802e201000000001976a9147f094a25bed0445a0a774d6bc88280a5549233a788ac31349403000000001976a914d95e7aaaa7df2f66ed2c088262e4f92efc5247f488ac27729603000000001976a914a74250ce609235f0cd8422cfe9de8f29fa1a560388ac5c786d04000000001976a9148049a10b8bcbd1753c3448aa8a47cb63e1a76d2388ac8df70507000000001976a91436ac8e916da2e2b7d3edbe3735ac436c792394ca88acbdac8109000000001976a9142302f988bff71660c84dc5b083fb21acd3badf2288ac3276f10e000000001976a9144caa4f376d1610c5f829cb7df140811b0ddcde0688ac46f49c1d000000001976a9140bce96733b2f9aeeac119ce0796f86f15e914cd688aca589b41e000000001976a91498a363846cf127f9229f9b669766d4373e632b7b88ac2cf36a26000000001976a9141c9bf21b6fc4f6196b2536f0616f1ebcf719fe0e88ac37ad982f000000001976a9141626a6d283c27a679b80b7314020c57435842c5088ac28c20041000000001976a91418606b1283882d53a87790dd7c1134fb9bd8896f88ac7c7c3b5a000000001976a914d2c7073b788ddd945e60cf9ca3dbf0e5801681d888ac9031e965000000001976a9144ec7a62482568064e4dbc8d928126664e49f82d488ac1f07c2da000000001976a91432451908436a5e4cc556a30450d3514066c1887088ac140200000100000001ec5b235eb55e19bee0ec66604f3879d8fcd866eb684aa44b088af9ab32f28716000000006b4830450221008a6c3fbf07a3d21a868efaf9e55af06d11a8658f428939746e6bc74d8cf7bdf2022003ee55d33c9c9c0864757476b218d6cd1123f32ecbd3f0454bf31b886b91b7f901210349836aed9ccfc8794fcc9fd89e409ba4c103d11fd825980c387b290971dad2f7feffffff14d5454d00000000001976a91465cad2ae0812688c5f23353a8b7fc251ff63e66488ac97a6b000000000001976a9146e85ea6a67de5e5f235ffea0f0d70abb63334abe88acd4768d01000000001976a914cbe5df0a74a2843ba79e5e68a8ea3384732544ed88ac20cae501000000001976a914efb81f11aedf0f31b1751c44d68010b5ba0172be88acf4407303000000001976a9147f094a25bed0445a0a774d6bc88280a5549233a788acba348505000000001976a914d95e7aaaa7df2f66ed2c088262e4f92efc5247f488ac51db3506000000001976a9140bce96733b2f9aeeac119ce0796f86f15e914cd688ac80289707000000001976a91436ac8e916da2e2b7d3edbe3735ac436c792394ca88ac17cf4708000000001976a914b962152139ee24e4deb2ae25e4c7151cbca199cf88aca6ef1d0c000000001976a9148049a10b8bcbd1753c3448aa8a47cb63e1a76d2388ac395d1c0d000000001976a9144caa4f376d1610c5f829cb7df140811b0ddcde0688acfa3df413000000001976a9142302f988bff71660c84dc5b083fb21acd3badf2288acbaceaa17000000001976a914a74250ce609235f0cd8422cfe9de8f29fa1a560388acd0177b23000000001976a9141c9bf21b6fc4f6196b2536f0616f1ebcf719fe0e88ac51050826000000001976a91498a363846cf127f9229f9b669766d4373e632b7b88ac62d4652a000000001976a91418606b1283882d53a87790dd7c1134fb9bd8896f88ac63965e2d000000001976a9141626a6d283c27a679b80b7314020c57435842c5088acd4b66d71000000001976a91432451908436a5e4cc556a30450d3514066c1887088ac0e53107b000000001976a914d2c7073b788ddd945e60cf9ca3dbf0e5801681d888ac87137ba4000000001976a9144ec7a62482568064e4dbc8d928126664e49f82d488ac15020000"),SER_NETWORK, PROTOCOL_VERSION);
    stream >> block;

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    // Match the first transaction
    filter.insert(uint256S("0x5211f6c82d2d3687afe6b6ae90424fe8199f7f1fe1c3c2d70275ea28638b2c1b"));

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 1);
    pair<unsigned int, uint256> pair = merkleBlock.vMatchedTxn[0];

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == uint256S("0x5211f6c82d2d3687afe6b6ae90424fe8199f7f1fe1c3c2d70275ea28638b2c1b"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 0);

    vector<uint256> vMatched;
    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);

    // Match an output from the second transaction (the pubkey for address 1DZTzaBHUDM7T3QvUKBz4qXMRpkg8jsfB5)
    // This should match the third transaction because it spends the output matched
    // It also matches the fourth transaction, which spends to the pubkey again
    filter.insert(ParseHex("0100000003822c03d57f61b05110b54b578682ae7805528bf2cd063ad693c48c63619db6fd000000006b48304502210090a416bd51b2db3ff156c9484e516cb9022593fa5b262efd5451ce3319cd3bf4022003c112390baf3d05e31c8f1d8825e16537b5d48a3431e016df2f80b42cd5b258012102f49998de3177c380b46123133f7cdcd4ef89760111cb39b7f9fffd4d710a7764feffffffcecb99c4a951ea5bdd9b88b5c25fc95298ca0a52cb2f85b104f7207074e1d82f000000006a4730440220247214bd1646d1d0cf5379e27c02277ac9bfd28119c7bb4b2f17befb92c0142c0220340f40236d7981fdd61bf413ab35fe6cf3b4dd1907804f0858746699cd890d7301210349836aed9ccfc8794fcc9fd89e409ba4c103d11fd825980c387b290971dad2f7feffffffef43f5c22f075224078907394e6ad8efb5b4348bb112b649b0703b306770829c000000006a47304402206c91a220f46bef22872b6dc2aa5a91a010ca2023f411f800b9857578383563290220228f9de171de8e440756eb3363ec0776aad6df421f78c0a38aabcb1c5c93521d012102333ac4b9b36d923bc018f229b2a364761b22720d606124df8295c1c6c77beef2feffffff10e6480f00000000001976a9146aa8633c695ee4b0b1b0c7da50e4a9bb5f63675788ac1802e201000000001976a9147f094a25bed0445a0a774d6bc88280a5549233a788ac31349403000000001976a914d95e7aaaa7df2f66ed2c088262e4f92efc5247f488ac27729603000000001976a914a74250ce609235f0cd8422cfe9de8f29fa1a560388ac5c786d04000000001976a9148049a10b8bcbd1753c3448aa8a47cb63e1a76d2388ac8df70507000000001976a91436ac8e916da2e2b7d3edbe3735ac436c792394ca88acbdac8109000000001976a9142302f988bff71660c84dc5b083fb21acd3badf2288ac3276f10e000000001976a9144caa4f376d1610c5f829cb7df140811b0ddcde0688ac46f49c1d000000001976a9140bce96733b2f9aeeac119ce0796f86f15e914cd688aca589b41e000000001976a91498a363846cf127f9229f9b669766d4373e632b7b88ac2cf36a26000000001976a9141c9bf21b6fc4f6196b2536f0616f1ebcf719fe0e88ac37ad982f000000001976a9141626a6d283c27a679b80b7314020c57435842c5088ac28c20041000000001976a91418606b1283882d53a87790dd7c1134fb9bd8896f88ac7c7c3b5a000000001976a914d2c7073b788ddd945e60cf9ca3dbf0e5801681d888ac9031e965000000001976a9144ec7a62482568064e4dbc8d928126664e49f82d488ac1f07c2da000000001976a91432451908436a5e4cc556a30450d3514066c1887088ac14020000"));

    merkleBlock = CMerkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 1);
	
    BOOST_CHECK(pair == merkleBlock.vMatchedTxn[0]);
	
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == uint256S("0x5211f6c82d2d3687afe6b6ae90424fe8199f7f1fe1c3c2d70275ea28638b2c1b"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 0);

    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
	{
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);
	}	
	
}

BOOST_AUTO_TEST_CASE(merkle_block_2_with_update_none)
{
    // Random real block (00000981af837857722e4b116a339cbf9fc094f795476a78ca195ba45a3d4882)
    // With 4 txes
    CBlock block;
    CDataStream stream(ParseHex("00000020ec0a3a347373bd94f030a47ad2ae9fcf942f87bd21e0f412510913250808000010c48120f39469877250b651fc54f88e11666dcb9cf4b652eb618517ac88274b01000000000000000000000000000000000000000000000000000000000000008f059f5a01940f1e7d02c1938d9b88064e47dede6fdee258318672773d43e702a1737f0c42c700000301000000010000000000000000000000000000000000000000000000000000000000000000ffffffff050259020104ffffffff01f4d154a102000000232102e76d4d03308f4d8870aa330d500eec46459c031a8679beba690c05a5ac63ef01ac0000000001000000026662bc32fb7f5cbb88f0a43a4d5b20dbaf77fccb4037c5cfed6039b1e591aa66000000006a4730440220735ee7f32bb35210d94c15c8db8dc345695f03099dcd3461444f9ee918c448d302200d305fa424cf2e045389ceee9ba6b62f11dab5cc5a547a22fafe6cd3e28149760121036c8b386236ba4afe80fe11e2c0742b88c1903ce8dbf8c1259fae72fed615da0ffeffffffa18cce5a0ba86a7714db9b562157732299736c2b22e83d256b373bf63f304d00000000006b483045022100db46e268bd865dfc795c97002aaa0c4ecd3a94a7171bcee34bb5de698b88b3b1022063ba2561347382714b7f201615aa7ccfda7ae7b052b0048977e94bfcea8e4fdf012102d8408529ab6d82c822ebf20e5ad101922b4462a8a53e063a1f5297ba50cc7ccefeffffff02884cbb06000000001976a9145609d3cba885642a58c6b83ef965451b74e9abc788ac5cb4989a020000001976a914786ecb40da7e99700f52bdbb6ec4e818a157457288ac2b020000010000000200a56a5cc1cb624616cc0b7d03308213c1e24551beb84dec48c429751093ba63000000006a47304402205f51c8fad376c442d4c67958d26ae3366a57144fd513d395c35a25d3e567b37902206a732a450bd5af4f52a257df848ba8cdce10b8f1d215252441b2cad1a4ef306301210349836aed9ccfc8794fcc9fd89e409ba4c103d11fd825980c387b290971dad2f7feffffff7174a11fc3d02ee5e9c47f5fbdb2e5d4e8fdbdae2f4f6bd9e216c95dc61688d9000000006b483045022100b22a2e5187b2d347b2e295a2adab3a806ef0fcc83569572621b7c0699d51587702205171ea3d43a7fd9522bf778bfdd65f809b783bb037f0c110e54b6d45303eba370121034ea65e4415eae2c53a08ff695d0f01b5fdc9f5b44d2e41d3900bcf4ea2fc471afeffffff1178a91100000000001976a9143bc4c5f50cf37e066c33c3d961c5dfd72da9016c88aca1a2b300000000001976a914332dc578f088985feff91bb525f04707d8a64e1c88ac46f9e503000000001976a9147f094a25bed0445a0a774d6bc88280a5549233a788ac88ab7d04000000001976a91471a70813f182f6844ead3856880cc8396cdf115f88ac628b9c05000000001976a914d2c7073b788ddd945e60cf9ca3dbf0e5801681d888ac6443650a000000001976a91436ac8e916da2e2b7d3edbe3735ac436c792394ca88ac6443650a000000001976a914d95e7aaaa7df2f66ed2c088262e4f92efc5247f488ac17e5970f000000001976a91433104010fb77f804d162988c4210f2fae801357888ac5cde7d13000000001976a914b962152139ee24e4deb2ae25e4c7151cbca199cf88ac352f1716000000001976a914b3953e752d8e47d8b8cf4ff92b8b96a6d32415a488ac5fbcf528000000001976a9140f9bff04443d562b37e93fd77ffe1ae9cbb9328d88ac70006f30000000001976a9148049a10b8bcbd1753c3448aa8a47cb63e1a76d2388acc55e1840000000001976a9141c9bf21b6fc4f6196b2536f0616f1ebcf719fe0e88acb53d3442000000001976a91498a363846cf127f9229f9b669766d4373e632b7b88ac2f7bae65000000001976a9143b47d49c010a50d76401df3eeb3fb8c395145ee788acfd4ddf7d000000001976a914a74250ce609235f0cd8422cfe9de8f29fa1a560388ace7ff347f000000001976a91418606b1283882d53a87790dd7c1134fb9bd8896f88ac58020000"),SER_NETWORK, PROTOCOL_VERSION);
    stream >> block;

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_NONE);
    // Match the first transaction
    filter.insert(uint256S("0x1f5ac80b3d26c50ffd143d98adfd53d529aca80d4dbd18c8c40d5a7d829234aa"));

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 1);
    pair<unsigned int, uint256> pair = merkleBlock.vMatchedTxn[0];

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == uint256S("0x1f5ac80b3d26c50ffd143d98adfd53d529aca80d4dbd18c8c40d5a7d829234aa"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 0);

    vector<uint256> vMatched;
    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);

    // Match an output from the second transaction (the pubkey for address 1DZTzaBHUDM7T3QvUKBz4qXMRpkg8jsfB5)
    // This should not match the third transaction though it spends the output matched
    // It will match the fourth transaction, which has another pay-to-pubkey output to the same address
    filter.insert(ParseHex("76a914786ecb40da7e99700f52bdbb6ec4e818a157457288ac"));

    merkleBlock = CMerkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 1);

    BOOST_CHECK(pair == merkleBlock.vMatchedTxn[0]);

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == uint256S("0x1f5ac80b3d26c50ffd143d98adfd53d529aca80d4dbd18c8c40d5a7d829234aa"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 0);
    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched) == block.hashMerkleRoot);

    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);
}

BOOST_AUTO_TEST_CASE(merkle_block_3_and_serialize)
{
    // Random real block (00001fe1acd1d99ca594fb2173374362b76290abc497a2207967e1ccd419f773)
    // With one tx
    CBlock block;
    CDataStream stream(ParseHex("00000020f0e814567b3ee95a0325e14408d7add3aaac8c44c1092be4ff4693921b9a020072027d72303c4b459824ad29dfec2795092a624b255ea759d0505e568827e0160100000000000000000000000000000000000000000000000000000000000000ca3c9e5af7c8041f2700320ffe9a87e52a10ab852b6bd8e32e03cfe2cf2cbd1f16da3a39554c00000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff040178010bffffffff01c06f54a102000000232103c13416fa90fc1ba75bf1fe5265e996a32ec2a5c094176a7e7435ec80639f811fac00000000"), SER_NETWORK, PROTOCOL_VERSION);
    stream >> block;

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    // Match the only transaction
    filter.insert(uint256S("0x16e02788565e50d059a75e254b622a099527ecdf29ad2498454b3c30727d0272"));

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 1);

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == uint256S("0x16e02788565e50d059a75e254b622a099527ecdf29ad2498454b3c30727d0272"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 0);

    vector<uint256> vMatched;
    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);

    CDataStream merkleStream(SER_NETWORK, PROTOCOL_VERSION);
    merkleStream << merkleBlock;
	
    vector<unsigned char> vch = ParseHex("00000020f0e814567b3ee95a0325e14408d7add3aaac8c44c1092be4ff4693921b9a020072027d72303c4b459824ad29dfec2795092a624b255ea759d0505e568827e0160100000000000000000000000000000000000000000000000000000000000000ca3c9e5af7c8041f2700320ffe9a87e52a10ab852b6bd8e32e03cfe2cf2cbd1f16da3a39554c0000010000000172027d72303c4b459824ad29dfec2795092a624b255ea759d0505e568827e0160101");
    vector<char> expected(vch.size());

    for (unsigned int i = 0; i < vch.size(); i++)
        expected[i] = (char)vch[i];

    BOOST_CHECK_EQUAL_COLLECTIONS(expected.begin(), expected.end(), merkleStream.begin(), merkleStream.end());
}

BOOST_AUTO_TEST_CASE(merkle_block_4)
{
    // Random real block (000015bbbef3f1d90b99ce29219c1760f129959b63f3c2df0ebe45a9f4f8a2cb)
    // With 7 txes
    CBlock block;
    CDataStream stream(ParseHex("000000206a199f91b45c4aa58dd5ee53a3595bc91e74294d575acb04a8f99d2634140000906fe917cd72b7d898d9b73508b351fd821e0749ac1936ba11ee150e1d2cadeb010000000000000000000000000000000000000000000000000000000000000061299f5a8a64161e76ddb66d865e8feae48389f4d7e1923f93733548a87a0adfdfeab1be9f0bf2940401000000010000000000000000000000000000000000000000000000000000000000000000ffffffff160287020461299f5a0d2f5374726174756d506f6f6c2f0000000002f270999a020000001976a914788541a7f20b86328ceb935e9a284a35ef58259788ac52bbbb06000000001976a914788541a7f20b86328ceb935e9a284a35ef58259788ac00000000010000000217635a2170a6f1ad56f982c71784d68866b958f4286000d504578957b8c84c47000000006a47304402204bf19d15560bda632069d9aa436dbd0bb4cef801109ee1017a140c67f63da456022007522cb9677dc530a15ee9766be69c1117ee430d16b1f165331a15d67013b79f01210349836aed9ccfc8794fcc9fd89e409ba4c103d11fd825980c387b290971dad2f7feffffff27a0d1c8eb1f137334daf9503dcaa61591c703dc0dcc78712678078102ffd593000000006a47304402205865bafc1349a5abe990c02c72c3cf347683fedebcf090bac52e4f2c9bcfeec1022004b07e43256838ac207d4c2b5de5e8fce985d4e0ce60e71db3addb82c6889efe012102803ca4272c648f2907d8efb642008134fb4b9f6d59ab42101330897673ff0badfeffffff0bde391500000000001976a914dd0c929e53754636a20308686d803a4e89efa2ab88acaaf50c0e000000001976a914132443a6068466762ff519b40f032c359876440a88acaaf50c0e000000001976a914b962152139ee24e4deb2ae25e4c7151cbca199cf88ac0052e80f000000001976a9140f9bff04443d562b37e93fd77ffe1ae9cbb9328d88acfde0262a000000001976a91433104010fb77f804d162988c4210f2fae801357888aca0bfb22b000000001976a91498a363846cf127f9229f9b669766d4373e632b7b88ac30f9cf47000000001976a914a74250ce609235f0cd8422cfe9de8f29fa1a560388ac1aa3c44b000000001976a9148049a10b8bcbd1753c3448aa8a47cb63e1a76d2388ac5849896c000000001976a91418606b1283882d53a87790dd7c1134fb9bd8896f88acf6a2747e000000001976a9143b47d49c010a50d76401df3eeb3fb8c395145ee788ac21932a9a000000001976a9141c9bf21b6fc4f6196b2536f0616f1ebcf719fe0e88ac8602000001000000031369b477a8da39aac7a2e08f7074134ac5063b421a12f7ac8a53b0d60fb4ad62000000006b483045022100add42072679298a0aa47fc3c36e43a400b74370aa98b991a36ec53ae0f302114022020cac9f84e51f95f0642014daf401aaa220e3a2c7e471c1134afcbd09449090f012102b7464665dd963304567e352c496592049b67da2259003c05dcde0abdc7290ab7feffffff45c9d5f0f323b9928bf5e9125e920fa597cbdbd674c855ac5e311a5722fb3b34000000006a473044022028c5f61171c1d6789d5bf3b100f3dc7022772e6b8d167e46b476d17adeacad4702200925ca3806dd0a617dd8ae60ce5f797fab196987b52cbd2985ed4ea36f619a89012102ed89b5289537e07a7c0cb0d57b9fa09ff2e5e262e3e2762f4a96fecc411575affeffffffa30a75afe5b0016100e5e5eaf73f927f656f996dc9ec6958bcb464a4f6f1f905000000006a47304402203d5a64faf0660db011e0c970ab7c784b815b3303478675ae85d0f2440e54d08f0220754e2e98714f2b11fee5d65dc702a0dd30e65d7c81aa4b18848e9e0ffcd488ca01210349836aed9ccfc8794fcc9fd89e409ba4c103d11fd825980c387b290971dad2f7feffffff10edd01400000000001976a91481fd7e19327536e4ccb07cfd53740f0c47de6a5788ac231f5b01000000001976a91433104010fb77f804d162988c4210f2fae801357888ac98ac8f02000000001976a91436ac8e916da2e2b7d3edbe3735ac436c792394ca88ac1a748807000000001976a914d2c7073b788ddd945e60cf9ca3dbf0e5801681d888acebafb407000000001976a91471a70813f182f6844ead3856880cc8396cdf115f88acbe5c1708000000001976a914efb81f11aedf0f31b1751c44d68010b5ba0172be88ac72ff4309000000001976a914b3953e752d8e47d8b8cf4ff92b8b96a6d32415a488ac93996d17000000001976a91498a363846cf127f9229f9b669766d4373e632b7b88ac2d07f624000000001976a914a74250ce609235f0cd8422cfe9de8f29fa1a560388ac8344aa25000000001976a914d95e7aaaa7df2f66ed2c088262e4f92efc5247f488ac3c510526000000001976a9141c9bf21b6fc4f6196b2536f0616f1ebcf719fe0e88ac9db8322d000000001976a914b962152139ee24e4deb2ae25e4c7151cbca199cf88acf500c732000000001976a9148049a10b8bcbd1753c3448aa8a47cb63e1a76d2388accb2cb33b000000001976a9140f9bff04443d562b37e93fd77ffe1ae9cbb9328d88aca3418778000000001976a9143b47d49c010a50d76401df3eeb3fb8c395145ee788ac5f2e89da000000001976a91418606b1283882d53a87790dd7c1134fb9bd8896f88ac860200000100000001d30fd2da2cd5edd597e5ec486331b57b574028e3d14f413d2ea2ae9c09ebec9c000000006b483045022100acc25b99408ca19c8e90d2c1f5c5b6d9204a08156e77d65db1f43d71b9b558810220397b4910dd5ccdd9a45ac2ec6728df1ec2000619a8373c15e555d52952a8f7aa01210349836aed9ccfc8794fcc9fd89e409ba4c103d11fd825980c387b290971dad2f7feffffff1194a1ba00000000001976a914582b97cf086874509fefc665d3811425a7426b5b88acdcd6e200000000001976a914d2c7073b788ddd945e60cf9ca3dbf0e5801681d888ac9584a802000000001976a914132443a6068466762ff519b40f032c359876440a88ac298d8a04000000001976a914332dc578f088985feff91bb525f04707d8a64e1c88ac502afb05000000001976a9147f094a25bed0445a0a774d6bc88280a5549233a788ac07e03306000000001976a914d95e7aaaa7df2f66ed2c088262e4f92efc5247f488acf1767e13000000001976a91433104010fb77f804d162988c4210f2fae801357888ac1890b515000000001976a914b962152139ee24e4deb2ae25e4c7151cbca199cf88ac3fa9ec17000000001976a91436ac8e916da2e2b7d3edbe3735ac436c792394ca88ac1e70e91b000000001976a914b3953e752d8e47d8b8cf4ff92b8b96a6d32415a488ac8455b729000000001976a9140f9bff04443d562b37e93fd77ffe1ae9cbb9328d88acd155202d000000001976a9141c9bf21b6fc4f6196b2536f0616f1ebcf719fe0e88ac05245a34000000001976a91498a363846cf127f9229f9b669766d4373e632b7b88ac81f3ff37000000001976a9148049a10b8bcbd1753c3448aa8a47cb63e1a76d2388ac0ddf7967000000001976a91418606b1283882d53a87790dd7c1134fb9bd8896f88ac9da8c174000000001976a914a74250ce609235f0cd8422cfe9de8f29fa1a560388ac607d2189000000001976a9143b47d49c010a50d76401df3eeb3fb8c395145ee788ac79020000"),SER_NETWORK, PROTOCOL_VERSION);
    stream >> block;

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    // Match the last transaction
    filter.insert(uint256S("0x43b8ced49f4626174806456cf79e4bc2465249bfc5a4a83d83bd67e63eecee3b"));

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());
	
    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 1);
    pair<unsigned int, uint256> pair = merkleBlock.vMatchedTxn[0];

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == uint256S("0x43b8ced49f4626174806456cf79e4bc2465249bfc5a4a83d83bd67e63eecee3b"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 3);

    vector<uint256> vMatched;
    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);

    // Also match the 4th transaction
    filter.insert(uint256S("0x76fc7a9690a04ec4c9f3233cd8a45abf5bcebeba76491c5502f3f81eb8d753b0"));
    merkleBlock = CMerkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 2);

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == uint256S("0x76fc7a9690a04ec4c9f3233cd8a45abf5bcebeba76491c5502f3f81eb8d753b0"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 0);

    BOOST_CHECK(merkleBlock.vMatchedTxn[1] == pair);

    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);
}

BOOST_AUTO_TEST_CASE(merkle_block_4_test_p2pubkey_only)
{
    // Random real block (00000f86cee5c9278ddbed302531862b2dfd3202798ec46ca2f8fe314edaff83)
    // With 7 txes
    CBlock block;
    CDataStream stream(ParseHex("0000002021dfb06c2c724edde1a79c062b2717f75c5138ff9a1e48f647bd67630d0f0000485251a85d7e929396d97bdf633bbbd35a55a297a9abf94f9786f8624913931c0000000000000000000000000000000000000000000000000000000000000000e7ead65a03e41b1e2d0448f201466234deb2cde542035a7019a402f0ff522cb33f5d55d7048e00000201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff050212610102ffffffff01f88c54a102000000232102cacdab64d818935f8d6b737974bb40209e424d2e3df6f18365c485150e141ba7ac0000000001000000026c1cb33e35788de1f909d1917703ba91a348f1ef57af916257eeb51708f6a22f010000006a473044022073f8f87fdbc5d0d2d6dd73d88a447ba0215af2c20ccaa8813b07765d0298331a022028c931a69f28f75c550fc6e698d99263185772ec98c990855e4a9404d04e613901210229805d998f27a14963e1108cfbeefd493cce0329095b9a521ece402c9b505cd4feffffffb311d009f0e9e85e8dee7be8b7ca8d693a4462cac14f332762ac3091baf1271e010000006b483045022100f70e93c1f3c3e7661429f2ee8170471854e27f0619d4e03cc55bedb48125f409022032132e2eb766e648e19b53028c20ca51eec85fbb50d5dfe8dd96166b58a2cb1901210229805d998f27a14963e1108cfbeefd493cce0329095b9a521ece402c9b505cd4feffffff02008c8647000000001976a9146942832bc53d31e2ecad09ce4d2f6c103549188d88acc81e9160040000001976a914d51abc7669dcf27752a481ef9711f39f06c4d8f988ac10610000"),SER_NETWORK, PROTOCOL_VERSION);
    stream >> block;

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_P2PUBKEY_ONLY);
    // Match the generation pubkey
    filter.insert(ParseHex("02cacdab64d818935f8d6b737974bb40209e424d2e3df6f18365c485150e141ba7"));
    // ...and the output address of the 4th transaction
    filter.insert(ParseHex("5c13652f0da782d756d6b92fcd52fb5eeeb272a6"));

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    // We should match the generation outpoint
    BOOST_CHECK(filter.contains(COutPoint(uint256S("0x37da235d0566c91b7fd5f41e7861b63ee8c6ff3ab0f37a39ab128fa5aafc25f8"), 0)));
    // ... but not the 4th transaction's output (its not pay-2-pubkey)
    BOOST_CHECK(!filter.contains(COutPoint(uint256S("0x02981fa052f0481dbc5868f4fc2166035a10f27a03cfd2de67326471df5bc011"), 0)));
}

BOOST_AUTO_TEST_CASE(merkle_block_4_test_update_none)
{
    // Random real block (000000000000b731f2eef9e8c63173adfb07e41bd53eb0ef0a6b720d6cb6dea4)
    // With 7 txes
    CBlock block;
    CDataStream stream(ParseHex("0000002021dfb06c2c724edde1a79c062b2717f75c5138ff9a1e48f647bd67630d0f0000485251a85d7e929396d97bdf633bbbd35a55a297a9abf94f9786f8624913931c0000000000000000000000000000000000000000000000000000000000000000e7ead65a03e41b1e2d0448f201466234deb2cde542035a7019a402f0ff522cb33f5d55d7048e00000201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff050212610102ffffffff01f88c54a102000000232102cacdab64d818935f8d6b737974bb40209e424d2e3df6f18365c485150e141ba7ac0000000001000000026c1cb33e35788de1f909d1917703ba91a348f1ef57af916257eeb51708f6a22f010000006a473044022073f8f87fdbc5d0d2d6dd73d88a447ba0215af2c20ccaa8813b07765d0298331a022028c931a69f28f75c550fc6e698d99263185772ec98c990855e4a9404d04e613901210229805d998f27a14963e1108cfbeefd493cce0329095b9a521ece402c9b505cd4feffffffb311d009f0e9e85e8dee7be8b7ca8d693a4462cac14f332762ac3091baf1271e010000006b483045022100f70e93c1f3c3e7661429f2ee8170471854e27f0619d4e03cc55bedb48125f409022032132e2eb766e648e19b53028c20ca51eec85fbb50d5dfe8dd96166b58a2cb1901210229805d998f27a14963e1108cfbeefd493cce0329095b9a521ece402c9b505cd4feffffff02008c8647000000001976a9146942832bc53d31e2ecad09ce4d2f6c103549188d88acc81e9160040000001976a914d51abc7669dcf27752a481ef9711f39f06c4d8f988ac10610000"),SER_NETWORK, PROTOCOL_VERSION);
    stream >> block;

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_NONE);
    // Match the generation pubkey
    filter.insert(ParseHex("64d818935f8d6b737974bb40209e424d2e3df6f18365c485150e141ba7"));
    // ...and the output address of the 4th transaction
    filter.insert(ParseHex("5c13652f0da782d756d6b92fcd52fb5eeeb272a6"));

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    // We shouldn't match any outpoints (UPDATE_NONE)
    BOOST_CHECK(!filter.contains(COutPoint(uint256S("0x37da235d0566c91b7fd5f41e7861b63ee8c6ff3ab0f37a39ab128fa5aafc25f8"), 0)));
    BOOST_CHECK(!filter.contains(COutPoint(uint256S("0x02981fa052f0481dbc5868f4fc2166035a10f27a03cfd2de67326471df5bc041"), 0)));
}

static std::vector<unsigned char> RandomData()
{
    uint256 r = GetRandHash();
    return std::vector<unsigned char>(r.begin(), r.end());
}

BOOST_AUTO_TEST_CASE(rolling_bloom)
{
    // last-100-entry, 1% false positive:
    CRollingBloomFilter rb1(100, 0.01);

    // Overfill:
    static const int DATASIZE=399;
    std::vector<unsigned char> data[DATASIZE];
    for (int i = 0; i < DATASIZE; i++) {
        data[i] = RandomData();
        rb1.insert(data[i]);
    }
    // Last 100 guaranteed to be remembered:
    for (int i = 299; i < DATASIZE; i++) {
        BOOST_CHECK(rb1.contains(data[i]));
    }

    // false positive rate is 1%, so we should get about 100 hits if
    // testing 10,000 random keys. We get worst-case false positive
    // behavior when the filter is as full as possible, which is
    // when we've inserted one minus an integer multiple of nElement*2.
    unsigned int nHits = 0;
    for (int i = 0; i < 10000; i++) {
        if (rb1.contains(RandomData()))
            ++nHits;
    }
    // Run test_ulord with --log_level=message to see BOOST_TEST_MESSAGEs:
    BOOST_TEST_MESSAGE("RollingBloomFilter got " << nHits << " false positives (~100 expected)");

    // Insanely unlikely to get a fp count outside this range:
    BOOST_CHECK(nHits > 25);
    BOOST_CHECK(nHits < 175);

    BOOST_CHECK(rb1.contains(data[DATASIZE-1]));
    rb1.reset();
    BOOST_CHECK(!rb1.contains(data[DATASIZE-1]));

    // Now roll through data, make sure last 100 entries
    // are always remembered:
    for (int i = 0; i < DATASIZE; i++) {
        if (i >= 100)
            BOOST_CHECK(rb1.contains(data[i-100]));
        rb1.insert(data[i]);
    }

    // Insert 999 more random entries:
    for (int i = 0; i < 999; i++) {
        rb1.insert(RandomData());
    }
    // Sanity check to make sure the filter isn't just filling up:
    nHits = 0;
    for (int i = 0; i < DATASIZE; i++) {
        if (rb1.contains(data[i]))
            ++nHits;
    }
    // Expect about 5 false positives, more than 100 means
    // something is definitely broken.
    BOOST_TEST_MESSAGE("RollingBloomFilter got " << nHits << " false positives (~5 expected)");
    BOOST_CHECK(nHits < 100);

    // last-1000-entry, 0.01% false positive:
    CRollingBloomFilter rb2(1000, 0.001);
    for (int i = 0; i < DATASIZE; i++) {
        rb2.insert(data[i]);
    }
    // ... room for all of them:
    for (int i = 0; i < DATASIZE; i++) {
        BOOST_CHECK(rb2.contains(data[i]));
    }
}

BOOST_AUTO_TEST_SUITE_END()
