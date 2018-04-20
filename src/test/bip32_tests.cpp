// Copyright (c) 2013-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include "base58.h"
#include "key.h"
#include "uint256.h"
#include "util.h"
#include "utilstrencodings.h"
#include "test/test_ulord.h"

#include <string>
#include <vector>
using namespace std;


struct TestDerivation {
    std::string pub;
    std::string prv;
    unsigned int nChild;
};

struct TestVector {
    std::string strHexMaster;
    std::vector<TestDerivation> vDerive;

    TestVector(std::string strHexMasterIn) : strHexMaster(strHexMasterIn) {}

    TestVector& operator()(std::string pub, std::string prv, unsigned int nChild) {
        vDerive.push_back(TestDerivation());
        TestDerivation &der = vDerive.back();
        der.pub = pub;
        der.prv = prv;
        der.nChild = nChild;
        return *this;
    }
};

TestVector test1 =
  TestVector("000102030405060708090a0b0c0d0e0f")
    ("tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp",
     "tprv8ZgxMBicQKsPeDgjzdC36fs6bMjGApWDNLR9erAXMs5skhMv36j9MV5ecvfavji5khqjWaWSFhN3YcCUUdiKH6isR4Pwy3U5y5egddBr16m",
     0x80000000)
    ("tpubD8eQVK4Kdxg3gHrF62jGP7dKVCoYiEB8dFSpuTawkL5YxTus5j5pf83vaKnii4bc6v2NVEy81P2gYrJczYne3QNNwMTS53p5uzDyHvnw2jm",
     "tprv8bxNLu25VazNnppTCP4fyhyCvBHcYtzE3wr3cwYeL4HA7yf6TLGEUdS4QC1vLT63TkjRssqJe4CvGNEC8DzW5AoPUw56D1Ayg6HY4oy8QZ9",
     1)
    ("tpubDApXh6cD2fZ7WjtgpHd8yrWyYaneiFuRZa7fVjMkgxsmC1QzoXW8cgx9zQFJ81Jx4deRGfRE7yXA9A3STsxXj4CKEZJHYgpMYikkas9DBTP",
     "tprv8e8VYgZxtHsSdGrtvdxYaSrryZGiYviWzGWtDDKTGh5NMXAEB8gYSCLHpFCywNs5uqV7ghRjimALQJkRFZnUrLHpzi2pGkwqLtbubgWuQ8q",
     0x80000002)
    ("tpubDDRojdS4jYQXNugn4t2WLrZ7mjfAyoVQu7MLk4eurqFCbrc7cHLZX8W5YRS8ZskGR9k9t3PqVv68bVBjAyW4nWM9pTGRddt3GQftg6MVQsm",
     "tprv8gjmbDPpbAirVSezBEMuwSu1Ci9EpUJWKokZTYccSZSomNMLytWyLdtDNHRbucNaRJWWHANf9AzEdWVAqahfyRjVMKbNRhBmxAM8EJr7R15",
     2)
    ("tpubDFfCa4Z1v25WTPAVm9EbEMiRrYwucPocLbEe12BPBGooxxEUg42vihy1DkRWyftztTsL23snYezF9uXjGGwGW6pQjEpcTpmsH6ajpf4CVPn",
     "tprv8iyAReWmmePqZv8hsVZzpx4KHXRyT4chmHdriW95m11R8Tyi3fDLYDM93bq4NGn1V6eCu5cE3zSQ6hPd31F2ApKXkZgTyn1V78pHjkq1V2v",
     1000000000)
    ("tpubDHNy3kAG39ThyiwwsgoKY4iRenXDRtce8qdCFJZXPMCJg5dsCUHayp84raLTpvyiNA9sXPob5rgqkKvkN8S7MMyXbnEhGJMW64Cf4vFAoaF",
     "tprv8kgvuL81tmn36Fv9z38j8f4K5m1HGZRjZY2QxnXDy5PuqbP6a5TzoKWCgTcGHBu66W3TgSbAu2yX6sPza5FkHmy564Sh6gmCPUNeUt4yj2x",
     0);

TestVector test2 =
  TestVector("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")
    ("tpubD6NzVbkrYhZ4XJDrzRvuxHEyQaPd1mwwdDofEJwekX18tAdsqeKfxss79AJzg1431FybXg5rfpTrJF4iAhyR7RubberdzEQXiRmXGADH2eA",
     "tprv8ZgxMBicQKsPdqC56nGKYsarqYsgrSm33vCswnuMLFCk3gP7DFW5nPFExzSe7FGAzkbAFrxtXoQEe8vaX471tU3dsUUC7PNpYLGuzb2agmj",
     0)
    ("tpubD9ejmKSp2iP93ZpA8DJo25eVmY8sikSEBPZ2Q7y6pvs6a95rQufk7iSMidGtU64UDaTmPu5c4uJpTQVQ3rfqT2ZsshbJtaYuqutBhMEvKgw",
     "tprv8cxhcuQZtLhUA6nNEZeCcfzPCWcwZRFKc5xF7bvoQf4hjeq5nWr9wDpVYViSkK71QQpz9sNcxxpMzeZQ5Lc4phD2setFVsYZfkBUMsgR3x8",
     0xFFFFFFFF)
    ("tpubDAoo1vULQcZFDS2LYfJSVRL4AHMnGEbvGYdZKWssUfdV2SKK2o64KnDxL1X1Dpfa16PK3jwDN7jR85Mjpm9xBB2WQnDNFJoviJ9nYAGqm3T",
     "tprv8e7ksWS6GEsaKxzYf1dr61fwbFqr6uR1hF2n2zqa4Pq6Bx4YQQGU9Hc69rCRUZqVJe9svtaG1yKURtJAoiDCPzebJP7bGPGpTXX18KaUzow",
     1)
    ("tpubDDcmRwTGaFrSK3hUcKT1TNGHVpEHNRXBaz8RAaYCnYyvhGBULJcmDgcLAoi91hMrbGqrtP2T1F3FCsckjfauSWVR14RDTrF8e4pjnhENZ4d",
     "tprv8gvjHXR2RtAmRafgifnR3xcAvniMD6LH1gXdt4VuNHBXrmvhhuoB3BzTzeQ3WH3BcbWagBeeRWzgkb5KrbjaQUTtS9eQ7VFCwKwjbvD1VbH",
     0xFFFFFFFE)
    ("tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev",
     "tprv8i6mCVMP3H8UiXuHT9bxRUJMqXBiG4xn3PFXQnCKD3SnK8FdoajBZiMZdM8S8hRUAAoGz1RdotaGZiAhNYe56K94G6BiFhGqGuxFfgKQPiw",
     2)
    ("tpubDG9qJLc8hq8PMG7y4sQEodLSocEkfj4mGrUC75b7G76mDoqybcUXvmvRsruvLeF14mhixobZwZP6LwqeFePKU83Sv8ZnxWdHBb6VzE6zbvC",
     "tprv8jTo9vZtZTSiTo6BBDjeQDgLEaipWPsrhYsQpZYoqqJNPKbCyDewkHJZhkoSHiWYCUf1Gm4TFzQxcG4D6s1J9Hsn4whDK7QYyHHokJeUuac",
     0);

void RunTest(const TestVector &test) {
    std::vector<unsigned char> seed = ParseHex(test.strHexMaster);
    CExtKey key;
    CExtPubKey pubkey;
    key.SetMaster(&seed[0], seed.size());
    pubkey = key.Neuter();
    BOOST_FOREACH(const TestDerivation &derive, test.vDerive) {
        unsigned char data[74];
        key.Encode(data);
        pubkey.Encode(data);

        // Test private key
        CBitcoinExtKey b58key; 
		b58key.SetKey(key);
        BOOST_CHECK(b58key.ToString() == derive.prv);

        CBitcoinExtKey b58keyDecodeCheck(derive.prv);
        CExtKey checkKey = b58keyDecodeCheck.GetKey();
        assert(checkKey == key); //ensure a base58 decoded key also matches

        // Test public key
        CBitcoinExtPubKey b58pubkey; b58pubkey.SetKey(pubkey);
        BOOST_CHECK(b58pubkey.ToString() == derive.pub);

        CBitcoinExtPubKey b58PubkeyDecodeCheck(derive.pub);
        CExtPubKey checkPubKey = b58PubkeyDecodeCheck.GetKey();
        assert(checkPubKey == pubkey); //ensure a base58 decoded pubkey also matches

        // Derive new keys
        CExtKey keyNew;
        BOOST_CHECK(key.Derive(keyNew, derive.nChild));
        CExtPubKey pubkeyNew = keyNew.Neuter();
        if (!(derive.nChild & 0x80000000)) {
            // Compare with public derivation
            CExtPubKey pubkeyNew2;
            BOOST_CHECK(pubkey.Derive(pubkeyNew2, derive.nChild));
            BOOST_CHECK(pubkeyNew == pubkeyNew2);
        }
        key = keyNew;
        pubkey = pubkeyNew;
    }
}

BOOST_FIXTURE_TEST_SUITE(bip32_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bip32_test1) {
    RunTest(test1);
}

BOOST_AUTO_TEST_CASE(bip32_test2) {
    RunTest(test2);
}

BOOST_AUTO_TEST_SUITE_END()
