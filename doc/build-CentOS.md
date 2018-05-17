CentOS Build Notes
====================
Some notes on how to build Ulord Core in CentOS.

As a server OS, we suggest not to bother with the GUI.

Preparation
-------------

Run the following as root to install the base dependencies for building:

```bash
yum install -y qt-devel protobuf-devel qrencode-devel libevent-devel libtool openssl-devel

yum -y install python python-devel libicu libicu-devel zlib zlib-devel bzip2 bzip2-devel
```

### Building boost

Do not use `yum install -y boost-devel`! It's necessary to build boost, manually:

```
# Fetch the source and verify that it is not tampered with
wget https://dl.bintray.com/boostorg/release/1.67.0/source/boost_1_67_0.tar.gz
echo '8aa4e330c870ef50a896634c931adf468b21f8a69b77007e45c444151229f665  boost_1_67_0.tar.gz' | sha256 -c
# MUST output: (SHA256) boost_1_67_0.tar.gz: OK
tar zxf boost_1_67_0.tar.gz

# Build Boost 1.67.0 & Install
cd boost_1_67_0
./bootstrap.sh
./b2 install --prefix=/usr/local

# Set the environment
ldconfig
cd
vi .bashrc
LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
export LD_LIBRARY_PATH
:wq
source .bashrc
```

### Building BerkeleyDB

BerkeleyDB is only necessary for the wallet functionality. To skip this, pass `--disable-wallet` to `./configure`.

```bash
# Fetch the source and verify that it is not tampered with
wget http://download.oracle.com/berkeley-db/db-4.8.30.NC.tar.gz
echo '12edc0df75bf9abd7f82f821795bcee50f42cb2e5f76a6a281b85732798364ef  db-4.8.30.NC.tar.gz' | sha256 -c
# MUST output: (SHA256) db-4.8.30.NC.tar.gz: OK
tar -xzf db-4.8.30.NC.tar.gz

# Build the library and install to specified prefix
cd db-4.8.30.NC/build_unix/
#  Note: Do a static build so that it can be embedded into the executable, instead of having to find a .so at runtime
../dist/configure --enable-cxx --disable-shared --with-pic --prefix=/usr/local
make install
```

### Building Ulord Core

Preparation:
```bash
./autogen.sh
```

To configure with wallet:
```bash
./configure --without-gui
# If your gcc version is the default of CentOS( "4.8.5 20150623 (Red Hat 4.8.5-28) (GCC)" ), your need to
./configure --without-gui CFLAGS="-std=c99"
```

Build
```bash
make -j2
```
