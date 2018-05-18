What is Ulord ?
-------------

Ulord is a P2P value delivery public chain. Through building its blockchain underlying architecture and digital resource distribution protocols, it enables third-party developers to explore their own applications over open-source agreements to form a complete ecology of blockchain technology and applications. Based on various rules and protocols created by Ulord, it loads various types of digital resource application scenarios including text, pictures, music, video and software, providing a direct docking platform for information creators and consumers.

UlordChain Documentation and Usage Resources
---------------

![](https://avatars0.githubusercontent.com/u/35293052?s=200&v=4)

Resources may be helpful to know about Ulord.

Basic usage resources:

* [Official site](http://ulord.one/)
* [Whitepaper](http://ulord.one/whitepaper/web/viewer.html?lang=zh)
* [Downloads](http://ulord.one/download.html)

General Info about Ulord:

* [Community](https://www.jianshu.com/c/a63d65402fd7)

What is UlordChain?
------------------

UlordChain is a infrastructure chain layer and adopts the mixed consensus mechanism of POW and POS.It supports the intermediate layer and top application layer of the Ulord.
UlordChain is the infrastructure of the whole ecosystem.

Building UlordChain
-------------------

### Build on Ubuntu(16.04 LTS)

    git clone https://github.com/UlordChain/UlordChain.git

Install dependency

    sudo apt-get install build-essential libtool autotools-dev automake pkg-config libssl-dev libevent-dev bsdmainutils
    sudo apt-get install libboost-system-dev libboost-filesystem-dev libboost-chrono-dev libboost-program-options-dev libboost-test-dev libboost-thread-dev
    sudo apt-get install software-properties-common
    sudo add-apt-repository ppa:bitcoin/bitcoin
    sudo apt-get update
    sudo apt-get install libdb4.8-dev libdb4.8++-dev
    sudo apt-get install libminiupnpc-dev
    sudo apt-get install libzmq3-dev

    # QT 5, for GUI
    sudo apt-get install libqt5gui5 libqt5core5a libqt5dbus5 qttools5-dev qttools5-dev-tools libprotobuf-dev protobuf-compiler    
    # optional
    sudo apt-get install libqrencode-dev

Configure and build

    ./autogen.sh
    ./configure
    make -j(number of threads)

### Run

    cd src && ./ulordd -daemon # use ./ulord-cli to make rpc call

Development Process
-------------------

The master branch is constantly updated and developed, while stable
and versionized executables will be published once mainnet is published.

Issues and commit changes are welcome.

Testing
-------

Tests are placed in /tests directory.

