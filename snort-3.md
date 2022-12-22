**Install Snort-3 on ubuntu-18**

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
 
 ##**Install Gperftools**(google’s thread-caching malloc (used in chrome). Tcmalloc is a memory allocator that’s optimized for high concurrency situations which will provide better speed for the trade-off of higher memory usage. We don’t want the version of tcmalloc from the repositories (version 2.5 in libgoogle-perftools-dev) as they don’t work with Snort. Tcmalloc is optional but recommended:)
    
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
  ```
  `./configure_cmake.sh --prefix=/usr/local --enable-tcmalloc`
  
  After successful completion of complition you will see output like this
  
      ```
            snort version 3.1.47.0

                  Install options:
                      prefix:     /usr/local
                      includes:   /usr/local/include/snort
                      plugins:    /usr/local/lib/snort

                  Compiler options:
                      CC:             /usr/bin/cc
                      CXX:            /usr/bin/c++
                      CFLAGS:            -fvisibility=hidden   -DNDEBUG -g -ggdb  -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free  -O2 -g -DNDEBUG
                      CXXFLAGS:          -fvisibility=hidden   -DNDEBUG -g -ggdb  -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free  -O2 -g -DNDEBUG
                      EXE_LDFLAGS:
                      MODULE_LDFLAGS:

                  Feature options:
                      DAQ Modules:    Static (afpacket;bpf;dump;fst;gwlb;nfq;pcap;savefile;trace)
                      libatomic:      System-provided
                      Hyperscan:      OFF
                      ICONV:          ON
                      Libunwind:      ON
                      LZMA:           ON
                      RPC DB:         Built-in
                      SafeC:          OFF
                      TCMalloc:       ON
                      JEMalloc:       OFF
                      UUID:           ON
                  -------------------------------------------------------

                  -- Configuring done
                  -- Generating done
                  -- Build files have been written to: /root/snort_src/snort3-3.1.47.0/build
            ```
        
Execute below command for installation      
      
      cd build
      make
      make install
      ldconfig
      
      
After successfully installation

      ```
               root@k8samit-1:~/snort_src/snort3-3.1.47.0/build# snort -V

            _     -*> Snort++ <*-
            o"  )~   Version 3.1.47.0
                 By Martin Roesch & The Snort Team
                 http://snort.org/contact#team
                 Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
                 Copyright (C) 1998-2013 Sourcefire, Inc., et al.
                 Using DAQ version 3.0.10
                 Using LuaJIT version 2.1.0-beta3
                 Using OpenSSL 1.1.1  11 Sep 2018
                 Using libpcap version 1.8.1
                 Using PCRE version 8.39 2016-06-14
                 Using ZLIB version 1.2.11
                 Using LZMA version 5.2.2
       ```

**Configuring Snort**

Get the interface name

 `iface=$(ip route | grep default | awk '{print $5}')`
 
 you will need to set your network interface on promiscuous mode so that it can be able to see all of the network traffic sent to it.
 
 `ip link set dev $iface promisc on`
 
 To verify the promisc changes: 
 
`ip add sh $if | grep -i promisc`
      
**Install Snort Rules**

```
mkdir /usr/local/etc/rules

wget -qO- https://www.snort.org/downloads/community/snort3-community-rules.tar.gz | tar xz -C /usr/local/etc/rules/
```

Edit the snort configuration file:
    vi /usr/local/etc/snort/snort.lua
   
 Define your network as shown below:
     
    HOME_NET = '10.128.0.22/32'
    EXTERNAL_NET = '!$HOME_NET'
      
    ips =
      {
          -- use this to enable decoder and inspector alerts
          --enable_builtin_rules = true,

          -- use include for rules files; be sure to set your path
          -- note that rules files can include other rules files
          -- (see also related path vars at the top of snort_defaults.lua)

          variables = default_variables,
          rules = [[ include /usr/local/etc/rules/snort3-community-rules/snort3-community.rules ]]
      }


To check/test the config file 
    
      snort -c /usr/local/etc/snort/snort.lua -R /usr/local/etc/rules/snort3-community-rules/snort3-community.rules
    
**Install Snort OpenAppID**

OpenAppID is a plugin that allows Snort to detect various applications, Facebook, Netflix, Twitter, and Reddit, used in the network.
      
Download and unpack it with following command:
      
      wget https://www.snort.org/downloads/openappid/26425 -O OpenAppId-26425.tgz
      tar -xzvf OpenAppId-26425.tgz
      
Next, copy the OpenAppID binary file to the system directory:

       cp -R odp /usr/local/lib/
      
Next, edit the Snort configuration file and define your OpenAppID location:
      
      vi /usr/local/etc/snort/snort.lua
      
      
                  #Near Line 98
                  appid =
                        {
                              app_detector_dir = '/usr/local/lib',
                              log_stats = true,
                              -- appid requires this to use appids in rules
                              --app_detector_dir = 'directory to load appid detectors from'
                        }
      
      
After making above changes make sure snort is able to read the appID from that path with below command:
      
      snort -c /usr/local/etc/snort/snort.lua --warn-all
      
Create log directory:
      
      mkdir /var/log/snort
      
      
**Create Snort Custom Rules**

You can also create your own custom rules as per your requirement. Let's create a custom rules for incoming ICMP request:

            vi /usr/local/etc/rules/local.rules

Add the following line:

                  alert icmp any any -> $HOME_NET any (msg:"ICMP connection test"; sid:1000001; rev:1;)
            
Next, verify the rules with the following command:
             
             snort -c /usr/local/etc/snort/snort.lua -R /usr/local/etc/rules/local.rules
             
Next, run the following command to start the Snort on your network interface using your custom rules:

             snort -c /usr/local/etc/snort/snort.lua -R /usr/local/etc/rules/local.rules -i eth0 -A alert_fast -s 65535 -k none
             
**Create a Systemd Service File for Snort**
            
 `vi /etc/systemd/system/snort3.service`
            
            
                        [Unit]
                        Description=Snort Daemon
                        After=syslog.target network.target

                        [Service]
                        Type=simple
                        ExecStart=/usr/local/bin/snort -c /usr/local/etc/snort/snort.lua -s 65535 -k none -l /var/log/snort -D -i eth0 -m 0x1b -u root -g root
                        ExecStop=/bin/kill -9 $MAINPID

                        [Install]
                        WantedBy=multi-user.target
            
            
Save and close the file, then reload the systemd daemon with the following command:

`systemctl daemon-reload`
            
Next, start and enable the Snort service with the following command:

`systemctl enable --now snort3`
            
You can now verify the status of the Snort using the following command:

`systemctl status snort3`
