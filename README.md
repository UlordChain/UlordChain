Ulord Core staging tree 0.12.1
===============================

official site 
=============
[ulord](http://ulord.org/)

Modifications for testing
-----------------------------
1. Commented out DNS seeding code in chainparams.cpp.
2. Commented out masternode syncing & IBD condition checks in miner.cpp.
3. Commented out masternode number check in masternode-sync.cpp in ProcessTick.
4. Disabled argument externalip out-routable condition check.
5. To replace libsodium.a with libsodium.so in Makefile.am to reduce ulordd & ulord-cli program size.
6. Changed MAX_HEADERS_RESULTS from 2000 to 160 to make BOOST_STATIC_ASSERT in chainparams.cpp to be true.
7. Unit tests are not usable currently.
8. Changed budget, superblock starting height to 2.

License
-------

Ulord Core is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/licenses/MIT.

