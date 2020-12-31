`net_*` - Tools for Processing Network Traffic
==

Copyright (C) 2017-2020 Christian Wressnegger ([@chwress](https://twitter.com/chwress))

There are plenty of tools for processing network traffic and PCAP files out there with [Wireshark](https://www.wireshark.org) and [tshark](https://www.wireshark.org/docs/man-pages/tshark.html) leading the way. I am not pretending to do anything better than these and as a matter of fact, `net_*` merely is a set of wrappers around tshark plus a little extra pre/post processing.

So why is this necessary? For me it was the need to (efficiently) reassemble TCP streams. There are (again) plenty of other tools doing exactly this ([tcpflow](https://github.com/simsong/tcpflow), [PcapPlusPlus](https://github.com/seladb/PcapPlusPlus/tree/master/Examples/TcpReassembly), or even using [Scapy](https://github.com/deeso/scapy-tcp-extractor)). All of them are doing a reasonably good job, but reassembly is hard. Also Wireshark and tshark let you reassemble TCP streams, of course, but oddly only one at a time. This sucks!

#### `net_*` to the rescue!

Considering Wireshark and tshark as the gold standard for everything that is related to the analysis of network traffic, `net_*` provides wrappers around these tools to enable TCP reassembly of all TCP streams in a PCAP file **without** re-reading the entire file over and over again. The idea is simple. Tshark allows you to determine session IDs for each packet/frame in captured network traffic (`net_stats`). With this information, we can easily write packets to individual, stream-specific files depending on their session ID (`net_extract streams`). Moreover, it might make sense to also filter the packets with sessions in mind (`net_filter`). The actual reassembly is then done by tshark based on these individual, much smaller PCAP files that contain exactly one TCP stream each -- the output is somewhat odd, though, such that we have to convert these conversations somehow (`net_conv`). Together, these individual steps allow us to reassemble TCP streams much faster (`net_reassemble`).


# Dependencies

Required:
- Python >= 3.6
- tshark
- [dpkt](https://dpkt.readthedocs.io/en/latest/) (this is automatically installed in a virtual env)

Optional:
- GNU Parallel

# Install

There is no real installation procedure. Just check out the repository,

```
$ git clone https://github.com/chwress/net_star.git
$ cd net_star
```

install the dependencies (for instance, for a Debian based system)

```
$ apt install python3 tshark parallel
```

and you should be good to go. That's it! ¯\\_(ツ)_/¯

# Tools

`net_*` consists out of a number of individual tools:

- `bin/net_conv ...`  
  Convert tshark conversation output into something useful.
- `bin/net_extract {packets,payloads,streams} ...`  
  Extract entire packets, payloads at different levels, or all TCP streams there are.
- `bin/net_filter {stats,packets} ...`  
  Filter network `net_stats` statistics per stream or packets in a PCAP file.
- `bin/net_reassemble ...`  
  Reassemble TCP sessions at scale.
- `bin/net_stats ...`  
  Determine network statistics using tshark.

# Examples

Let me briefly sketch the use of `net_*` based on a very simple, two-step example. For this, I have prepares a small script for downloading (and merging) sample captures from <https://wireshark.org>:

```
$ res/fetch_data.sh
```

Subsequently, we try to first filter **out** all X11 traffic from a PCAP file and then reassemble all TCP session. If you have a look at what sort of data is fetched, you quickly notice that this showcase is not super-elaborated but merely a simple toy example.

**Attention! The following is using GNU Parallel**

```
$ res/examples/filter_X11.sh "res/data/"
```

It creates another directory under `res/data/` containing pcap files without any X11 streams. These in turn can then get reassembled using the following commands:

```
$ bin/net_reassemble "res/data/out-excl:;X11;/x11-ipp.pcap"
$ ls -1 "res/data/out-excl:;X11;/out/x11-ipp.pcap"
0-in.tar.gz
0-out.tar.gz
0.pcap
1-in.tar.gz
1-out.tar.gz
1.pcap
2-in.tar.gz
2-out.tar.gz
2.pcap
```

If you would like to include all X11 data stream you can either adjust `filter_X11.sh` and remove the `--excl` argument or you could also use `net_reassemble` directly:

```
$ bin/net_reassemble "res/data/x11-ipp.pcap" ";X11;"
$ ls -1 "res/data/out-incl:;X11;/x11-ipp.pcap"
3-in.tar.gz
3-out.tar.gz
3.pcap
```



# Troubleshooting

I guess there are going to surface a couple problems with these tools sooner or later. One thing that I stumbled over is the following:

## PCAP-ng

A while ago wireshark's/tshark's default output is in `pcap-ng` format. `dpkt` (or the libpcap wrapper?) is not able to process these. Please make sure to operate in `pcap` format. If necessary please convert our pcap file using Wireshark's `editcap`:

```
editcap "$old" "$new" -F pcap
```

Alternatively, the `-F` program argument is provided for the other tools that come with Wireshark as well (e.g., `mergecap`, ...)
