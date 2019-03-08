What is Ulord ?
-------------
           uuu                              
       uuuuuuuuuuu                          
      uuuuuuuuuuuuu                         
      uuuuuuuuuuuuu                         
      uuuuuuuuuuuuu                         
      uuuuuuuuuuuuu                         
      uuuuuuuuuuuuu                  u      
      uuuuuuuuuuuuu             uuuuuuuuuu  
      uuuuuuuuuuuuu             uuuuuuuuuuuu
      uuuuuuuuuuuuu                uuuuuuuuu
      uuuuuuuuuuuuu                  uuuuuuu
      uuuuuuuuuuuuu                  uuuuuuu
      uuuuuuuuuuuuu                  uuuuuuu
      uuuuuuuuuuuuu                  uuuuuuu
      uuuuuuuuuuuuu                  uuuuuuu
      uuuuuuuu      uuuuuuuuu        uuuuuuu
      uuuuu   uuuuuuuuuuu   u        uuuuuuu
       uu  uuuuuuuuu       uu        uuuuuuu
       uuuuuuuu         uu        uuuuuuu 
      uuuuuuu          uu        uuuuuuuu 
     uuuuuuu        uuuu         uuuuuuu  
    uuuuuuu        uuu         uuuuuuu    
    uuuuuuu        uu          uuuuuu   u  
    uuuuuuu       uu        uuuuuu    uuu  
    uuuuuu        uu    uuuuuuu    uuuuuu  
    uuuuuuu           uuuuu      uuuuuuuuu  
    uuuuuuu                  uuuuuuuuuuuuu  
    uuuuuuu                 uuuuuuuuuuuuuu  
    uuuuuuu                 uuuuuuuuuuuuuu  
    uuuuuuu                 uuuuuuuuuuuuuu  
    uuuuuuu                 uuuuuuuuuuuuuu  
    uuuuuuu                 uuuuuuuuuuuuuu  
    uuuuuuu                 uuuuuuuuuuuuuu  
       uuuu                 uuuuuuuuuuuuuu  
                            uuuuuuuuuuuuuu  
                            uuuuuuuuuuuuuu  
                             uuuuuuuuuuuuu  
                                 uuuuuu     


Ulord is a P2P value delivery public chain. By offering its blockchain infrastructure and digital resource distribution protocols, it enables third-party developers to explore their own applications over open-source agreements to form a complete ecology of blockchain technology and applications. Based on various rules and protocols created by Ulord, it loads various types of digital resource application scenarios including text, pictures, music, video and software, providing a direct docking platform for information creators and consumers.

UlordChain Documentation and Usage Resources
---------------
Resources may be helpful to know about Ulord.

Basic usage resources:

* [Official site](http://ulord.one/)
* [Whitepaper](http://ulord.one/whitepaper/web/viewer.html?lang=zh)
* [Downloads](http://ulord.one/download.html)

General Info about Ulord:

* [Community](https://ulorder.one/)

What is UlordChain?
------------------

UlordChain is a infrastructure chain layer and adopts the mixed consensus mechanism of POW and POS.It supports the intermediate layer and top application layer of the Ulord.
UlordChain is the infrastructure of the whole ecosystem.

Building UlordChain
-------------------

### Build on Ubuntu(16.04 LTS)

    git clone https://github.com/UlordChain/UlordChain.git

Install dependency
    sudo add-apt-repository ppa:bitcoin/bitcoin
    sudo apt-get update
    sudo apt-get install build-essential libtool autotools-dev automake pkg-config libssl-dev libevent-dev bsdmainutils libboost-system-dev libboost-filesystem-dev libboost-chrono-dev libboost-program-options-dev libboost-test-dev libboost-thread-dev software-properties-common libdb4.8-dev libdb4.8++-dev libminiupnpc-dev libzmq3-dev

    # QT 5, for GUI
    sudo apt-get install libqt5gui5 libqt5core5a libqt5dbus5 qttools5-dev qttools5-dev-tools libprotobuf-dev protobuf-compiler    
    # optional
    sudo apt-get install libqrencode-dev

Configure and make

    ./autogen.sh
    ./configure
    make -j(number of threads)

### Run

    cd src && ./ulordd -daemon 
    #You can use ./ulord-cli help  to obtain Ulord's commands.

Development Process
-------------------

The master branch is constantly updated and developed, while stable
and versionized executables will be published once mainnet is published.

Issues and commit changes are welcome.

Testing
-------
You can find the unit test cases [here](./src/test).
