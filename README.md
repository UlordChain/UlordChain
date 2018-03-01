What is Ulord ?
-------------

Ulord is a decentralized content distribution platform that provides content distribution in public chain based on blockchain technology, creates a complete ecosystem for content distribution by creative work, where people can create a wide variety of content-based decentralized applications, such as video, music, pictures, text, code, animation material, etc., and thus by taking advantage of the smart contract it ensures content creators and communicators get the corresponding benefits.

UlordChain Documentation and Usage Resources
---------------

![](http://ulord.one/images/ulordCnter.png)

Resources may be helpful to know about Ulord.

Basic usage resources:

* [Official site](http://ulord.one/)
* [Whitepaper](http://ulord.one/whitepaper/web/viewer.html?lang=zh)
* [Downloads](http://ulord.one/download.html)

General Info about Ulord:

* [Community](https://www.jianshu.com/c/a63d65402fd7)

What is UlordChain?
------------------

UlordChain is the basic layer of Ulord, a decentralized featured blockchain based on Dash Core, which supports 
intermediate layer and top application layer commands.

Building UlordChain
-------------------

### Build on Ubuntu(16.04 LTS)

    git clone https://github.com/UlordChain/UlordChain.git

Install dependency

    sudo apt-get install build-essential libtool autotools-dev automake pkg-config libssl-dev libevent-dev bsdmainutils
    sudo apt-get install libboost-system-dev libboost-filesystem-dev libboost-chrono-dev libboost-program-options-dev libboost-test-dev libboost-thread-dev
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

