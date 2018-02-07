Ulord Core staging tree 0.12.1
===============================

Modifications for testing
-----------------------------
1. commented out DNS seeding code in chainparams.cpp.
2. commented out masternode syncing & IBD condition checks in miner.cpp.
3. commented out masternode number check in masternode-sync.cpp in ProcessTick.
4. disabled argument externalip out-routable condition check.
5. to replace libsodium.a to libsodium.so in Makefile.am to reduce ulordd & ulord-cli program size.
6. changed MAX_HEADERS_RESULTS from 2000 to 160 to make BOOST_STATIC_ASSERT in chainparams.cpp to be true.
7. unit tests are not usable currently.
8. in chainparams.cpp, masternodepubkey & sporkpubkey have no corresponding private key.
9. changed budget, superblock starting height to 1500.

https://www.ulord.org
