Ulord Core 0.2
=====================

This is the official reference wallet for Ulord Token and comprises the backbone of the Ulord peer-to-peer network. You can [download Ulord Core](https://github.com/UlordChain) and [build it yourself](#building) using the guides below.

Running
---------------------
The following are some helpful notes on how to run Ulord on your native platform.

### Unix

Unpack the files into a directory and run:

- `bin/ulord-qt` (GUI) or
- `bin/ulordd` (headless)

### Windows

Unpack the files into a directory, and then run ulord-qt.exe.

### OS X

Drag Ulord-Qt to your applications folder, and then run Ulord-Qt.

### Need Help?

* Just raise the issues.

Building
---------------------
The following are developer notes on how to build Ulord Core on your native platform. They are not complete guides, but include notes on the necessary libraries, compile flags, etc.

- [OS X Build Notes](build-osx.md)
- [Unix Build Notes](build-unix.md)
- [Windows Build Notes](build-windows.md)
- [OpenBSD Build Notes](build-openbsd.md)
- [Gitian Building Guide](gitian-building.md)

Development
---------------------
The Ulord Core repo's [root README](/README.md) contains relevant information on the development process and automated testing.

- [Developer Notes](developer-notes.md)
- [Multiwallet Qt Development](multiwallet-qt.md)
- [Release Notes](release-notes.md)
- [Release Process](release-process.md)
- Source Code Documentation ***TODO***
- [Translation Process](translation_process.md)
- [Translation Strings Policy](translation_strings_policy.md)
- [Unit Tests](unit-tests.md)
- [Unauthenticated REST Interface](REST-interface.md)
- [Shared Libraries](shared-libraries.md)
- [BIPS](bips.md)
- [Dnsseed Policy](dnsseed-policy.md)

### Resources
* Discuss on the [UlordTalk](https://ulordtalk.org/) forums, in the Development & Technical Discussion board.
* Discuss on [#ulordpay](http://webchat.freenode.net/?channels=ulordpay) on Freenode. If you don't have an IRC client use [webchat here](http://webchat.freenode.net/?channels=ulordpay).

### Miscellaneous
- [Assets Attribution](assets-attribution.md)
- [Files](files.md)
- [Tor Support](tor.md)
- [Init Scripts (systemd/upstart/openrc)](init.md)

License
---------------------
Distributed under the [MIT software license](http://www.opensource.org/licenses/mit-license.php).
This product includes software developed by the OpenSSL Project for use in the [OpenSSL Toolkit](https://www.openssl.org/). 

Ulord Core 0.12.1
=====================

Intro
-----
Ulord is a P2P value delivery public chain. By offering its blockchain infrastructure and digital resource distribution protocols, it enables third-party developers to explore their own applications over open-source agreements to form a complete ecology of blockchain technology and applications. Based on various rules and protocols created by Ulord, it loads various types of digital resource application scenarios including text, pictures, music, video and software, providing a direct docking platform for information creators and consumers.


Setup
-----
Unpack the files into a directory and run ulord-qt.exe.

Ulord Core is the original Ulord client and it builds the backbone of the network.
However, it downloads and stores the entire history of Ulord transactions;
depending on the speed of your computer and network connection, the synchronization
process can take anywhere from a few hours to a day or more.

See the ulord wiki at:
  https://ulordpay.atlassian.net/wiki/
for more help and information.
