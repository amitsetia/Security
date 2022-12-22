Install Snort-3 on ubuntu-18

1. Install dependencies:
      apt-get update && apt install build-essential libpcap-dev libpcre3-dev libnet1-dev zlib1g-dev luajit hwloc libdnet-dev libdumbnet-dev bison flex liblzma-dev openssl libssl-dev pkg-config libhwloc-dev cmake cpputest libsqlite3-dev uuid-dev libcmocka-dev libnetfilter-queue-dev libmnl-dev autotools-dev libluajit-5.1-dev libunwind-dev libfl-dev bison flex -y

Install tools required for compiling the source from github:

  1. sudo apt-get install -y libtool git autoconf
  2. Download and Install Snort DAQ

      `git clone https://github.com/snort3/libdaq.git`
      
       Once the download is completed, navigate to the downloaded directory and configure it with the following command:
      ```
        cd libdaq
        ./bootstrap
        ./configure
   ```
      You should see the following output after successfully completion of ./configure
   ``` 
    cc:             gcc
    cppflags:
    am_cppflags:     -fvisibility=hidden -Wall -Wmissing-declarations -Wpointer-arith -Wcast-align -Wcast-qual -Wformat -Wformat-nonliteral -Wformat-security -Wundef -Wwrite-strings -Wextra -Wsign-compare -Wno-unused-parameter -fno-strict-aliasing -fdiagnostics-show-option
    cflags:         -g -O2
    am_cflags:       -Wstrict-prototypes -Wmissing-prototypes -Wold-style-definition -Wnested-externs
    ldflags:
    am_ldflags:
    libs:

    code_coverage_enabled:  no
    code_coverage_cppflags:
    code_coverage_cflags:
    code_coverage_ldflags:

    Build AFPacket DAQ module.. : yes
    Build BPF DAQ module....... : yes
    Build Divert DAQ module.... : no
    Build Dump DAQ module...... : yes
    Build FST DAQ module....... : yes
    Build netmap DAQ module.... : no
    Build NFQ DAQ module....... : yes
    Build PCAP DAQ module...... : yes
    Build Savefile DAQ module.. : yes
    Build Trace DAQ module..... : yes
    Build GWLB DAQ module...... : yes
    ```
 after that execute below command to install it:
 ```
 make
 make install
 ```
 
 ##Install Gperftools(google’s thread-caching malloc (used in chrome). Tcmalloc is a memory allocator that’s optimized for high concurrency situations which will provide better speed for the trade-off of higher memory usage. We don’t want the version of tcmalloc from the repositories (version 2.5 in libgoogle-perftools-dev) as they don’t work with Snort. Tcmalloc is optional but recommended:)
    ``` 
    wget https://github.com/gperftools/gperftools/releases/download/gperftools-2.10/gperftools-2.10.tar.gz
    tar xzf  gperftools-2.10.tar.gz
    cd gperftools-2.10
    ./configure #Compile it 
    
    #Install it with the following command:
      make
      make install
    ```
    
 ## Install Snort
  ```
  wget https://github.com/snort3/snort3/archive/refs/tags/3.1.47.0.tar.gz
  tar zxvf 3.1.47.0.tar.gz
  cd snort3-3.1.47.0/
  ./configure_cmake.sh --prefix=/usr/local --enable-tcmalloc
  ```
