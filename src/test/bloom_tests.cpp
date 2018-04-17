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
	int i = 0, count = 0;
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
	std::vector<unsigned char> ::iterator v_it;
	showbuf(stream);
	cout << endl;
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
	/*
	for(int i=0;i<merkleBlock.vMatchedTxn.size();i++)
	{
		cout << "i is \t" << i << "\t";
		cout << merkleBlock.vMatchedTxn[i].second.ToString() << endl;
		cout << merkleBlock.vMatchedTxn[i].first <<endl;
	}*/
	
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == uint256S("0x5211f6c82d2d3687afe6b6ae90424fe8199f7f1fe1c3c2d70275ea28638b2c1b"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 0);
/*
    BOOST_CHECK(merkleBlock.vMatchedTxn[2].second == uint256S("0x01d619300000000001d615d00000000001d614b000007f9e0000000100000000"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[2].first == 65);

    BOOST_CHECK(merkleBlock.vMatchedTxn[3].second == uint256S("00000000000000311149e2690fd93d61000000000000002d0000000000000001"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[3].first == 0);
*/
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
    for(int i=0;i<merkleBlock.vMatchedTxn.size();i++)
    {
        cout << "i is \t" << i << "\t";
        cout << merkleBlock.vMatchedTxn[i].second.ToString() << endl;
        cout << merkleBlock.vMatchedTxn[i].first <<endl;                                                            
    }


    merkleBlock = CMerkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 1);

    BOOST_CHECK(pair == merkleBlock.vMatchedTxn[0]);

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == uint256S("0x1f5ac80b3d26c50ffd143d98adfd53d529aca80d4dbd18c8c40d5a7d829234aa"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 0);
/*
    BOOST_CHECK(merkleBlock.vMatchedTxn[2].second == uint256S("0x3c1d7e82342158e4109df2e0b6348b6e84e403d8b4046d7007663ace63cddb23"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[2].first == 3);
*/
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
	
	for(int i =0;i<merkleBlock.vMatchedTxn.size();i++)
	{
		cout << "i is " << i << "\t";
		cout << merkleBlock.vMatchedTxn[i].first << endl;
		cout << merkleBlock.vMatchedTxn[i].second.ToString()<< endl;
	}
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

	cout << "merkleBlock.vMatchedTxn.size() is " << merkleBlock.vMatchedTxn.size() << endl;
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
    CDataStream stream(ParseHex("000000209900eb946f32af3233174105f6114e5f79a0e13c6361d6d1f927dcf0b40300005175c509a1c00c5cf06801abe301f39e0a67b630f374ea2422ef7a423b2c33900000000000000000000000000000000000000000000000000000000000000000a5d6d55aa3f6201e4eb5aa2a2ba48eae14c55b3d28f149d4c0129c720b6538c0b72459748a6e913c0701000000010000000000000000000000000000000000000000000000000000000000000000ffffffff21023f5f04a6d6d55a182f746573746e65742d706f6f6c2e756c6f72642e6f6e652f000000000264879b9a020000001976a9147cb13d22c94a993e4e42e39878781e989237385288acb8c0bb06000000001976a914788541a7f20b86328ceb935e9a284a35ef58259788ac00000000010000000a34efa031697e7f5c84325daf8d269cacebb52665e749c22d53bc2c20871f0563020000006a47304402204fb660cf313426175b26e24498ca172917bcc17f25546cd3af04aa2e065eeb1e02200272a5b3b02da36bab4ada882e82b92edfe46463eae661d65594e7180ccf762c01210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffff3f734486e9378c7b56fc642d8382309b872ec1c276de330ace807a218b1c05eb020000006b483045022100c873aaae82e1dddfafa7d95d201e5fa5f12775428a202aaf65efe4f32e1f9f5102206623672fb1ea33e47eb4895142a90343b430e6c0b0a5ec7df7e524f0b2d3163b01210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffff4c430433ebb9e39263312792a16b805fffa609704fab680d782facf203d27821020000006b483045022100a633438710bfe2c5db137fab5d24f70e375b067eb261d9660bf2b5bbcca84acc0220359c808d2150f767704a1c41fa4ac8016b63206afcfb48603ead9ce59630220701210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffff4d1c964e936c5b6ce83af9f0672ae20e6c2f24caaadb42929c3b80c864ca6c06000000006a473044022058f58a0c54477833c27e00f415fa1b86e290c69624405247ed3e5aa45b55228e022068edf9833c045c677cfa78f7135911409098409f1eadd056e0a12b83100b8650012103e64ae12ae32edd7b1eeac3b86614af73786b186ff07b60ca41b9c7b6bbd2c804feffffff66174549df582bac1ec37cdbcaf721953ac3835ea631b8a610e170ad9805a78f020000006a473044022031e9171756997bfcc681223e9713451b89a80a67bbe7147d1d096161c90c8f080220769e1511334f19c6ce53ec7f79170fb1ac9c6e503e06cc7886be428f0acda83001210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffff7d790ac51f98bd1ccb3d70bfedc0d7afc41a7009d8d512918a84a092da29cc2a010000006a47304402207c4b144105d421f06055b9ee9428b6958be9ff47cc224cec9b433eb1f191771e0220374f3648ec14fce4405a4d656cb69f006758366dc7f7ca6c31c2a7567d48028e012103319f473e8a6ae7b4cccd5ef86d161e77020d14201a980c992e775852984617c0feffffffb9c7adfe3695ef5af3c4d5479d4d1087f565c157e360b5822c85c3ee10854098020000006a47304402204d32ac64990af55a67689dcc8dc206230227be45d7dc8a0173626051880bc7a8022035817ee90be95a0fce2459b39e2ee8b919b11ae4acab609ccd14b0f2fb130a5801210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffffd774e0ce2afffe4c67978a91d5ab52d269bf435e889cc10d5b2e0a0400894517020000006a47304402202d78dd64a8f0c011d947eb09de9fc1211d697c49b6f1ae98b2633e6c9568c857022025dc82cedc3cba881c92850fb6eb7e9ac7f245997e529ac951319414cc49a7fd01210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffffef26799924cd3635c1ba09768f39b40b6560691840f4cd0fdee9832aa3462151020000006b483045022100c50282874dfd7ac05f02a9a68733029372b7400279678d2d837dc2ab29ceebc402204c1a9538052914c7424e26af02b485eaee29a80559f8bcb7b55a64516669755701210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967fefffffff21ef1c51495ae76a2788de6796a3c5fb74761fd9c2121447a08878bdfe51d5f020000006b483045022100e231d219e8b984520f8295563212c1f6c11bba74d3f174ce347e5542f6da6cea0220333f63ee3f46683e55a6068aa5a8a01ab8cad9bc008dca4e5e557b5ab4407a5d01210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffff0216841400000000001976a914edcae762e5710f8e5a6219befd105594b365be0f88ac00ca9a3b000000001976a9142d4c16e15f37ac1c2a9881212661b48000e308d188ac3e5f0000010000000a2f655d5f77446c5ca7e189ec436bbb5617abf9cbd8be161eb4984b4b589d97e1020000006a4730440220478155fcb9491250cf4b06a825b73a69dee89be140e0bd74c450a04fce5f9ad102204b22850ca94c3a2de68c7f3a6288fd78bb38006effaf422d6f3be707150d0b8501210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffff4f81790a11ef2f520117d997f6524db9c123990c327f4b418f56fae06313247e020000006a47304402202c3e29b66c06db6e0d8cd2019bfef94b74f144b6655dd3d5f55e13dd3f7f5a0702207424ce73b45dbeff448ad88f8fcd506b86a1de3777808b588b664b2c768a3e4101210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffff5082ef14199c60661c0e5529fbc044d3adb3d9b8ff2fd137db0e852823462787020000006b4830450221008645c8038bba75bddf3f627c27133110b98b0cf71fd192d4cb07ea206ece56c2022037545768f84f9bcff73691d7a99a4a8a8e4c1aaabce56a00d111085396d5a6c201210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffff626064d12632bbdb3efa0571742c746d059e6ca1f88402bcb426b32ad558f606000000006a47304402200769f3ba67a4f08b03bcb138c23b46fdfb94089a12b661352646f2ea1b0642e8022049616e7160d81962fc8768222a31def6982333f30f8a0916a5996a97807550c501210306cf44beccadbc4621be516e7e77fa8c1252642120bd458b79cfc582913763a6feffffff82407cdfa1cff474a5ab52ce680ea9afdfa6c0b61cb393dee18a373b64bbc2d3020000006b4830450221008f252777e9b815181001d19cef778446c462ce5ecd2358284b334727c9457fc802202346ea60f4e37e544188fcb31a54f38dd2aa3a3f57f40a2b5c145d40078521a401210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffff90233cd80b2c95dd4931128678f532b5c9c1ba983cbc7579995e9668aea5966f020000006b483045022100ac5381092fcfff5c51ab16db7c3b1fccfb2bc8852d34f18a18d157c2881f81da022019736c656bb06b6579bcab8ef3ed5305867c8da1a6f4d7eb5fca644b354bd65d01210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffff98125147870278bd7ff7dd041f5d664a71d22a1c0db645314589f318fea0db23020000006b483045022100a4e66273726f07901b8ff6284ccb1701ed81d8d88e15063887d78c890a14c83302207ef706399391fd951240feb1a9cfecfc3d99272c33dfb2d9d2f053870f72506401210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffff9c2864fe158ad86c50e4f9ebc4f150a215826096ccd1c1f8b1f1d8bcc859bcf0020000006a473044022056237dbede7927464dbdab85b860373b9d8a519d9399c3fb5ba44d46e38bcc8b02200bb992d78f8d9d44b2c83948059e2b7bfa88a7af0b3ce61747828e8e7d8b20e501210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffffa15bec8ced13519725bfd135f760b82334f821fce9ed5bb43b8b92551ff83cde010000006a473044022061c2b3b5823801cf90914f70ff363bc05d4c512ba0a547361f1179a24ede32c502207679bc6761d6daa5a4c323370abcdd3da10045d33f2f456edae80629aaea87b0012103fc30239014a8381f4b0f75d0d20620685214fe95e7c985ad6916f2d5557a7ebafeffffffb9d46fdf9432404e969907303e96171c05875672df425a1ea3c23bdcfcb79ee1020000006b483045022100b4e05017af601211d1a988c433d2c0df411bc1bc83173cd0634f682e9a37c48702203b9b7d3de1a793cb5cd1a8881d157038495c44e70cfeafdaf2ad361b654f198e012102e1b3790339ee92c46fab6bdf1fcfacf197f21e32469d253d9ce2d3fa980259cdfeffffff0236821400000000001976a914f359f58322938cbf0f0e3ef8ace3c56ac7b6fa9f88ac00ca9a3b000000001976a9142d4c16e15f37ac1c2a9881212661b48000e308d188ac3e5f0000010000000a175933f569ff2203937526d474274beedd1dc7007f38a0a88f8e9b044a8c79e0010000006b483045022100b2f6e9c0921d47d0155d9d40419ab392d0f7fdd647ab8d0c56e40f7c35e72de9022042b7e528f88428c04e6cbcfdf03b34045d4ce1de23596fc7452d5b3884c230e9012102b0c9109560081a897e53667ff096d57b6b1830a31b4e455610f19c5f88b0565bfeffffff21b44a4cdb69dd1b4402b6ce10f3a874d0fb294c241a468d37be58e2c0310758010000006b483045022100e076b8b2630be00c1eb01b73d4bbf567385e404ae89cdeba9be2b54e6401ae5102200a6be74d8d7485d29b07bd377f5cd498b5cc4be4862beb71d155383271ffff7a01210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffff366fb8b8d10146609bd8fb7f012a89733709ed94ca78ced2e0db99f21253a40e020000006a473044022008ef24167ef43a3f2bc91a9ff6f40329eb75b0f892ecd0c319dddfe6833941a4022021695867527f715352b18b24f8102791073b31487269496557b88abd63e65eb501210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffff496922d32b7960e4d2b8fb91cb439f50ab610392a7542cdb79055c0248dd4fc1020000006b483045022100bb44ab7d655ff501a943e61a5d3c2cfdb842032e67346c8581c18ea991d4d7360220082a69b61251b7f8bba42ab6a85e039a1c4558d19b14ac1c0517cdfb97b29f9201210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffff71457188eae1dc1dd00b111b792ece91eb753f6fd72dab3b92383fc249a3b82f020000006a473044022043a82c122a5c31cc0e6fdd71392f11a61d9761bb72aeaf127f0b239cff53425a022044c7b9639c916d6a403f35d8d1717f20b19e04c5ae74257a5d6a30c69f5c52f601210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffff9454b5d2bef1713c8c496a35917934684df06ab4e6ef76cbc4c1c59caa470a77020000006a47304402204b7d8e24752c9b68edea466b28cddf0d1fea47e320fe125afd4b6e6e4c6c3439022034144153882350fa0b779d2cbe47e30be7e2325dbe98fd4ae179029f29aaaaab01210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffffb8da6d428c413620cc7d7a373ee7387eda2a1abff6f45d4edf6efdc4eb6e7006020000006a4730440220021c9a3660c9111371759a9e59efd0c78f60f2cbaab4c3803fb4c687e9f8f8e802205ae1f2f5a06215e30cd29409a4f7e1f59554eef0840898a2f81fa621658f3c1301210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffffebbcb8e7cf3f5d3ec2af6a5325d8aef67468edc432d2fb86d5dc3ba98f82d862000000006a47304402201e9a7e6f2279715ac2893bfd3b3053a1d14238a6577efc351dcfe927508ef9ec02202dd41cfd70feaaac6001a9beb80aa124b5f69f00cb3bea88336651acc6dd2c54012103c8abf4b195dc976ad87b9ba94ff45a62ee5da20e8d8983de8e18b47078eb64b2fefffffff11637845661e4749ac89700a309bcc203d7d945b007b1d0bfc6a087dcbb9afb020000006a4730440220626f60a67fdc267d8507ccfdd45931f1e8ec1fe49c38ca18109ddf08cccee35f0220325f837e34e4835414d89277f401d8bbf7b920567736ee8a8bb7c52a8f10946a01210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967fefffffffc5c8327d35f994248d2a38c63de366c3d870b28d5f0ac803149943a6d261732020000006a47304402206e13095c257b598f4d66a074decbcce975a523cd644d2ffb50d1e374f484bd7702207cfb0329dc80d08a0224d389f1b251753cb52c3f6f00c90a6b8bb543be4dcaf801210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffff0261831400000000001976a914c5d969ab659b9f61250d82068f7803f606806a3188ac00ca9a3b000000001976a9142d4c16e15f37ac1c2a9881212661b48000e308d188ac3e5f0000010000000a08ed680cb124f417e3334bf5b2ac3a65602d38a8afa6a99976bdb15ca314e7e8010000006a47304402200d323e04c9bb28a7e5e360d517d95121fa96a6ce28fc555aff869e56216b0c1d02205c84caae49090e0215b8f83943a451239fff2f29ee8d9b7ac17fa2dbc31d43c4012103060ab4a39ff47f053903b835d1027a08de7eafbba1b1e96faf84d0ff77ceb881feffffff0989a749981976a647f11e22e8af1cb9fd30a29cc88bb9c27041376e79b4de80020000006b48304502210090d70799aeb8446f429e8f56321d48ebb3fa7e8729f5021992325f071b5aa8b902202c70609d3f0a58c8b61a000f1b5b1c34318aae6c71b6542e0dab1512aa7c2e3501210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffff4af48be0ff4634c5992d8893655084f86772b12d073768377ad5f5ffe26e5be9000000006a47304402204c8a77049222846d8171a23b7171c3402c69ece34daa26d2e04f11931e962be002207ec92925bafe87f60a4f24dd0163e683654d024fbe1fca03a821445421ffeb330121034606256c8c0c0f681735b6662494758d7ef7ed925e062ac6698c28cb99aa44d3feffffff6dbf3e6ceb3c0ec403603cacac8cc8b6c6cc9902337ee860e4821da9d2534b36020000006a473044022010c7438dbf015b379e8ce4649ced512e410648c8d98d86671a5a4101486e7750022064e3bf183e84a871743d5f6bae0308b9304756f273d760d50bf06d769afd570a01210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffff7f17aabed6f8099562629df9d334a9465f206ff8115040808d7c7191ad2ba42c020000006b483045022100d5902a7bd52022cd383232ad9219d595e6d6c292bbab68810e07c8bcf476dbe402202ad93adcc454e72456c686404ede0bd47e8736bf840f7c7cd2e364a33aa3004b01210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffffad008f98c14df9a9571936c788f74687c38578fba18c725a05071b24f975b094010000006b483045022100d9bdb55ea24facffe91d7e95c4a585bb64e502894a3ff780005c72e4a329e489022053546e4dd2e4e397fbd39293501a91ebaa81dc660c6876bcef95ca2f1b83d43d01210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffffb7ee0ad8269962add5d634854cbe53e2e2768e9cb0a198a6d25e62d58c71d3c7020000006a47304402200227bdf1aa4ed69230ee629c58dc85338ff7e90d5ca2b3a544784395a2039de4022005a418d2f42074963ba0cf537cee4d7d06b9695a5f8b63661d1d8a43137aa61b01210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffffc2ede473d8ace59f0c404d60f2bf9cfbe3290368ac7f42806bb8464109640969020000006a47304402207263ca1952bb3c1337fcd52fe393a2c5c3c9abbcc3e3fb10b580cc353fb603b80220306af66669a652c6f9517e0b8c8f39d07ade559784719255392ec34dedef4ac401210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffffe596148b8db92783064caae481e369502eceee60b3506a6f5103e283a9e7a586020000006a4730440220525fc5abee4634972bafded4651557ef7a3048edba845ea7336efbd725590e6f02201566a270a5ec9f71f0480254ff701d20b48e387225bb1863615ab8b08a829cb001210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967fefffffff30d3ef6d8aa1228f76d3eefb4587d189e79a04391cb74c29e15bcd7dc83f397020000006a4730440220018b071785df5836e82b6df246a36ee742fc21cb8073dcb92c61f84be423736402202d9487c37cd06bc50fe0c42fcff61390f2e1fec1df2fa8ce662f44b1fed6b49401210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffff0221831400000000001976a914e224d0023cec7b3e4184d7b7ad95aab0c621c31088ac00ca9a3b000000001976a9142d4c16e15f37ac1c2a9881212661b48000e308d188ac3e5f0000010000000a0b1a09b7544a0b8688d24c9a96b8930ac73721b573e1eb4d9fb3b4573fd6c067000000006a47304402207670215b515d2646bd5058c8e7924f70922a685b565bfd1b899f2c05c0200d7f02201a5cdac4539ff875d19d2bca474c4f5606f6aeb08aff90ca7e4530f17029b9810121025162c0f910e5ee8da75de494b64903a5e79dea41a0e7eb0c6221b62a1f03effcfeffffff3d1004f9f89f0e8a39208c04df91bced924935f329c624ef69510b5e92ba13e3020000006a47304402200c376d888c6a13072802289f81d5c9bacb7ea8d02b3a0a32f247e39bee73eb570220060bd56983179352e3d6abd61614ef8c4b22c06db714c68278e055e2da2f1f4a01210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffff61c35a523702a878e830c67a6eb8c7556b1a165850c73bf8e3a284f3caf2bec9010000006a47304402200c41305fe9ef2c2b68f69c3941d27a824ca67f7d4c2ad36cf94d91c81d437f74022049fa492524a34d25802a97e54782b86d16e44c9606a017447521faa5f7e8b771012102be9546258d42c42b89e35eebb1a3a8e6c030e1fd1e3620b8dab111e61d3c9901feffffff70e14bd6a69630d1708df3b4599d96107524847771d64fbb694b350124b607f7020000006a47304402206442f6a557084c1f806a70373b53786203b10b9fd333eceb9f4be0b902294d8c022078bc0f506cde2767d689a86b0867c1c77b86ecb86cd242a21b8fcf886d3cfcab01210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffff90c005cf5bf80419a12014a1ebe32a57170ca68a94055345027dd76552ad887f020000006b483045022100f7a83259fb8f0739e4b96822e52f8f569c893d4148ae9de48c446989c4f88f4c02207fce034c2fa00abdb90ceea766057d72dbb13de7910e94870fd6483edb890f8d01210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffff917c1f0c5612147bb6bae194601b393ad486fbee54a9a27d62a59f3a45b46075020000006a47304402202b694f0758304b9930a7c84a5878db2772c83efefb4a7cff291dfed003c287fe022071154595c50961dc3d9ee03191f3592a1194a5711857c06cc05fe8f4aac3917101210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffffb4a4378545bde41bccea7d1efbac1751f18763e321d5cf219a72fabbaaa3250e020000006b483045022100987db0e73e598b58c34e3eac8d12387489f1dbef5b047aba2f53b92c14d54b1002201b6a13f11de7625ff39db9caea6deff93cca81616bb510eb0a14842a1478875301210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967fefffffff1c85498c739f0ab31cf0eca3056fa42d9558b18af3a43f7f17f4b5364b686a6020000006a473044022071d75991629c092272c7655408b2da4c138c88a0e61b5b8b3ee60e7263c434ac0220311e2018f5e8cc4443ca4f69f3b22d3d632ecc7452a6cf6053b1ecbac89e0666012102e1b3790339ee92c46fab6bdf1fcfacf197f21e32469d253d9ce2d3fa980259cdfefffffff55b14be3d1b250d45eba15752ccf21156cf86b3d7de1d0e3a285fb3e31f53d2020000006a473044022007a696448d5eae293acb9356a7899e045d8db7be507760c245015368d620283702203602cf041b497c1197e20edf2c2d4fa186329dd11e592db08bd772972741b82301210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967fefffffff7988f22580da136aba0ae689308617760565c0548c14bb4650b84fa7b146c88020000006a47304402202fbd3f54377e1c44404254426ddb6c5600cfe0d255cc3591877dae431c4ecc3e02201ccd3f1ae658776eefb3c6e67392d87c559e0d82ae94f8e69a144c9ba426ebc701210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffff020e871400000000001976a914898e6f7d1fee59eb7f2628966331260c0702cdd388ac00ca9a3b000000001976a9142d4c16e15f37ac1c2a9881212661b48000e308d188ac3e5f0000010000000a1f87bbd3823ec72602fa7ea9399027aca58e2a08df6d0656d3e8df3e876579f0020000006b4830450221009d42f77f4e902a18543557486e00aeba897fc893cc074b373e6cd821f10ebb1402207b977b78e173d0faea2a00b6260d395d3322aa5497f202bce9772234ff2d645d01210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffff286633d0a46a3f1591915736167e2df6d2d52e28deb4d2a2f08f87022b75d81d020000006a473044022042de8dc2c7f88ded11d0cbae6cab3b8c35537d2e8207258be5b0d6408f40bcb6022004330b5b3f0779a9be5d73c1fb93d429bffd66a8cdc6966c2e13a0721c0a1069012102e1b3790339ee92c46fab6bdf1fcfacf197f21e32469d253d9ce2d3fa980259cdfeffffff2b197f5fc331b4501879465b56d3fd54a50676e78bb0ab788e47f313fdceafa9010000006b483045022100c0999617c2a664957efce41f241cb2f80affbaa27da91c95bbf867bcd3dc47cd02206f836451f41277eea723adfe4eb48b4c6ef755bae47c3d6588fe16c5950b57fb01210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffff549294812affeaca6132013af21ff780ebc85a9602ae75d45d2ce5ce5d1fede8020000006b483045022100d872d68fd1473bec6f859ba2f5620a7d0677fce6ce788cb751c44f17095e400002201adf865025f1a5e1538a363d3f476bbda16c3daaf50105a7812555df569fb16901210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffff61cccde276591010d8d74f86aff4be24bed96995e778cb678242437cdd5fa427010000006b483045022100e83b94abeae5e454b26d38e4d30d468cca5bbb64f3c12d599775a8bfd447cb3f022025c10c55988fd04d9498b93a96aa42e1c831321e266026a1d53799c5713c218c01210259b7c3cd4ec4daaf42b94a2e8e37e364be727345e40405143c5938537ae1568dfeffffff6f9618a1a034d846007d47263820937d32ddb6a733d0272ae094e16360646a01020000006a47304402206914168edfe4b8a8fed33ed6a9ec76ddff63809a1cbf263bd85e6c7629b094c002205436cd26cabd49b37a49ca167af81dcabdf088959155a466bf3615a9233b314301210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffff747e26794c9ac1547921ee713713b937b1618ec13d85361e4868721f9aa53da2020000006b4830450221009e09ecea624ea65ab013c5cd67f95f8ba395d29a69f8d579518e0b047a682f8f022027e463f5e590abe078e9d714a8495016b44d762019428e832a8990e5184e4b2001210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffffbd0666f42697a27ef3fa727b86178da0767aad6977f05fbab34bb0a1facad57f020000006b483045022100e876ef5dcf0cab17948f1ba17b70f85903f3b23f1964ea9cb863d1b88ddfb25c022046f4664594fde7e84f69c1ac0afe658e72be4639c422ac8e07eb1f6fa6259f6101210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffffbe734d1e13cfef13d0ba0f209fe188935ad6f5afc6ddd5372637205d1d5e83c7000000006b483045022100c38b78bcdc8f980dad6dfedfb0595f1064df2e4d0929f4130a1f568d52c0ed7402201f6469df63b095d3f527c4a0fb0fca13e111d41bda9ec1ea5c1fe8ab79054dc6012102155e9aca90c86814902600dfcde3dcbf0ed63634d369ddb309648ca82977ac73feffffffca33d4dc9cb08e01a342b627924d9e5c4cf9deaa4508e991feed7c7b4249ee7d010000006a473044022016497000640837ed8f3db291c864329f1a675eede52529764b2e8f62c9d75bc102204dda15eca7a379703f029501480975f8084f4beb71666fb33e8da84810212dff01210248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967feffffff022a841400000000001976a91406bf853f03f6dd245b85f0fa621677540c35e5d388ac00ca9a3b000000001976a9142d4c16e15f37ac1c2a9881212661b48000e308d188ac3e5f0000"),SER_NETWORK, PROTOCOL_VERSION);
    stream >> block;

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_P2PUBKEY_ONLY);
    // Match the generation pubkey
    filter.insert(ParseHex("0248d6238b1888bb3441baa0aaaf7aaf52f909ec5ed92c195b4ec2f1916f35a967"));
    // ...and the output address of the 4th transaction
    filter.insert(ParseHex("2d4c16e15f37ac1c2a9881212661b48000e308d1"));

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());
	for(int i =0 ; i< merkleBlock.vMatchedTxn.size();i++)
	{
		cout << "i is " << i << "\t";
		cout << merkleBlock.vMatchedTxn[i].second.ToString() << "\t" << merkleBlock.vMatchedTxn[i].first << endl;
	}

    // We should match the generation outpoint
    BOOST_CHECK(filter.contains(COutPoint(uint256S("0xdffa20991250ea1c411495c41fdfa5058d6b97a4df0e741e49e4acc2a3de24101"), 1)));
    // ... but not the 4th transaction's output (its not pay-2-pubkey)
    BOOST_CHECK(!filter.contains(COutPoint(uint256S("0x02981fa052f0481dbc5868f4fc2166035a10f27a03cfd2de67326471df5bc011"), 0)));
}

BOOST_AUTO_TEST_CASE(merkle_block_4_test_update_none)
{
    // Random real block (000000000000b731f2eef9e8c63173adfb07e41bd53eb0ef0a6b720d6cb6dea4)
    // With 7 txes
    CBlock block;
    CDataStream stream(ParseHex("0100000082bb869cf3a793432a66e826e05a6fc37469f8efb7421dc880670100000000007f16c5962e8bd963659c793ce370d95f093bc7e367117b3c30c1f8fdd0d9728776381b4d4c86041b554b85290701000000010000000000000000000000000000000000000000000000000000000000000000ffffffff07044c86041b0136ffffffff0100f2052a01000000434104eaafc2314def4ca98ac970241bcab022b9c1e1f4ea423a20f134c876f2c01ec0f0dd5b2e86e7168cefe0d81113c3807420ce13ad1357231a2252247d97a46a91ac000000000100000001bcad20a6a29827d1424f08989255120bf7f3e9e3cdaaa6bb31b0737fe048724300000000494830450220356e834b046cadc0f8ebb5a8a017b02de59c86305403dad52cd77b55af062ea10221009253cd6c119d4729b77c978e1e2aa19f5ea6e0e52b3f16e32fa608cd5bab753901ffffffff02008d380c010000001976a9142b4b8072ecbba129b6453c63e129e643207249ca88ac0065cd1d000000001976a9141b8dd13b994bcfc787b32aeadf58ccb3615cbd5488ac000000000100000003fdacf9b3eb077412e7a968d2e4f11b9a9dee312d666187ed77ee7d26af16cb0b000000008c493046022100ea1608e70911ca0de5af51ba57ad23b9a51db8d28f82c53563c56a05c20f5a87022100a8bdc8b4a8acc8634c6b420410150775eb7f2474f5615f7fccd65af30f310fbf01410465fdf49e29b06b9a1582287b6279014f834edc317695d125ef623c1cc3aaece245bd69fcad7508666e9c74a49dc9056d5fc14338ef38118dc4afae5fe2c585caffffffff309e1913634ecb50f3c4f83e96e70b2df071b497b8973a3e75429df397b5af83000000004948304502202bdb79c596a9ffc24e96f4386199aba386e9bc7b6071516e2b51dda942b3a1ed022100c53a857e76b724fc14d45311eac5019650d415c3abb5428f3aae16d8e69bec2301ffffffff2089e33491695080c9edc18a428f7d834db5b6d372df13ce2b1b0e0cbcb1e6c10000000049483045022100d4ce67c5896ee251c810ac1ff9ceccd328b497c8f553ab6e08431e7d40bad6b5022033119c0c2b7d792d31f1187779c7bd95aefd93d90a715586d73801d9b47471c601ffffffff0100714460030000001976a914c7b55141d097ea5df7a0ed330cf794376e53ec8d88ac0000000001000000045bf0e214aa4069a3e792ecee1e1bf0c1d397cde8dd08138f4b72a00681743447000000008b48304502200c45de8c4f3e2c1821f2fc878cba97b1e6f8807d94930713aa1c86a67b9bf1e40221008581abfef2e30f957815fc89978423746b2086375ca8ecf359c85c2a5b7c88ad01410462bb73f76ca0994fcb8b4271e6fb7561f5c0f9ca0cf6485261c4a0dc894f4ab844c6cdfb97cd0b60ffb5018ffd6238f4d87270efb1d3ae37079b794a92d7ec95ffffffffd669f7d7958d40fc59d2253d88e0f248e29b599c80bbcec344a83dda5f9aa72c000000008a473044022078124c8beeaa825f9e0b30bff96e564dd859432f2d0cb3b72d3d5d93d38d7e930220691d233b6c0f995be5acb03d70a7f7a65b6bc9bdd426260f38a1346669507a3601410462bb73f76ca0994fcb8b4271e6fb7561f5c0f9ca0cf6485261c4a0dc894f4ab844c6cdfb97cd0b60ffb5018ffd6238f4d87270efb1d3ae37079b794a92d7ec95fffffffff878af0d93f5229a68166cf051fd372bb7a537232946e0a46f53636b4dafdaa4000000008c493046022100c717d1714551663f69c3c5759bdbb3a0fcd3fab023abc0e522fe6440de35d8290221008d9cbe25bffc44af2b18e81c58eb37293fd7fe1c2e7b46fc37ee8c96c50ab1e201410462bb73f76ca0994fcb8b4271e6fb7561f5c0f9ca0cf6485261c4a0dc894f4ab844c6cdfb97cd0b60ffb5018ffd6238f4d87270efb1d3ae37079b794a92d7ec95ffffffff27f2b668859cd7f2f894aa0fd2d9e60963bcd07c88973f425f999b8cbfd7a1e2000000008c493046022100e00847147cbf517bcc2f502f3ddc6d284358d102ed20d47a8aa788a62f0db780022100d17b2d6fa84dcaf1c95d88d7e7c30385aecf415588d749afd3ec81f6022cecd701410462bb73f76ca0994fcb8b4271e6fb7561f5c0f9ca0cf6485261c4a0dc894f4ab844c6cdfb97cd0b60ffb5018ffd6238f4d87270efb1d3ae37079b794a92d7ec95ffffffff0100c817a8040000001976a914b6efd80d99179f4f4ff6f4dd0a007d018c385d2188ac000000000100000001834537b2f1ce8ef9373a258e10545ce5a50b758df616cd4356e0032554ebd3c4000000008b483045022100e68f422dd7c34fdce11eeb4509ddae38201773dd62f284e8aa9d96f85099d0b002202243bd399ff96b649a0fad05fa759d6a882f0af8c90cf7632c2840c29070aec20141045e58067e815c2f464c6a2a15f987758374203895710c2d452442e28496ff38ba8f5fd901dc20e29e88477167fe4fc299bf818fd0d9e1632d467b2a3d9503b1aaffffffff0280d7e636030000001976a914f34c3e10eb387efe872acb614c89e78bfca7815d88ac404b4c00000000001976a914a84e272933aaf87e1715d7786c51dfaeb5b65a6f88ac00000000010000000143ac81c8e6f6ef307dfe17f3d906d999e23e0189fda838c5510d850927e03ae7000000008c4930460221009c87c344760a64cb8ae6685a3eec2c1ac1bed5b88c87de51acd0e124f266c16602210082d07c037359c3a257b5c63ebd90f5a5edf97b2ac1c434b08ca998839f346dd40141040ba7e521fa7946d12edbb1d1e95a15c34bd4398195e86433c92b431cd315f455fe30032ede69cad9d1e1ed6c3c4ec0dbfced53438c625462afb792dcb098544bffffffff0240420f00000000001976a9144676d1b820d63ec272f1900d59d43bc6463d96f888ac40420f00000000001976a914648d04341d00d7968b3405c034adc38d4d8fb9bd88ac00000000010000000248cc917501ea5c55f4a8d2009c0567c40cfe037c2e71af017d0a452ff705e3f1000000008b483045022100bf5fdc86dc5f08a5d5c8e43a8c9d5b1ed8c65562e280007b52b133021acd9acc02205e325d613e555f772802bf413d36ba807892ed1a690a77811d3033b3de226e0a01410429fa713b124484cb2bd7b5557b2c0b9df7b2b1fee61825eadc5ae6c37a9920d38bfccdc7dc3cb0c47d7b173dbc9db8d37db0a33ae487982c59c6f8606e9d1791ffffffff41ed70551dd7e841883ab8f0b16bf04176b7d1480e4f0af9f3d4c3595768d068000000008b4830450221008513ad65187b903aed1102d1d0c47688127658c51106753fed0151ce9c16b80902201432b9ebcb87bd04ceb2de66035fbbaf4bf8b00d1cfe41f1a1f7338f9ad79d210141049d4cf80125bf50be1709f718c07ad15d0fc612b7da1f5570dddc35f2a352f0f27c978b06820edca9ef982c35fda2d255afba340068c5035552368bc7200c1488ffffffff0100093d00000000001976a9148edb68822f1ad580b043c7b3df2e400f8699eb4888ac00000000"), SER_NETWORK, PROTOCOL_VERSION);
    stream >> block;

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_NONE);
    // Match the generation pubkey
    filter.insert(ParseHex("04eaafc2314def4ca98ac970241bcab022b9c1e1f4ea423a20f134c876f2c01ec0f0dd5b2e86e7168cefe0d81113c3807420ce13ad1357231a2252247d97a46a91"));
    // ...and the output address of the 4th transaction
    filter.insert(ParseHex("b6efd80d99179f4f4ff6f4dd0a007d018c385d21"));

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    // We shouldn't match any outpoints (UPDATE_NONE)
    BOOST_CHECK(!filter.contains(COutPoint(uint256S("0x147caa76786596590baa4e98f5d9f48b86c7765e489f7a6ff3360fe5c674360b"), 0)));
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
