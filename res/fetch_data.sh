#!/bin/bash
my_dir=$(cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd)

cd "$my_dir/data"
wget "https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=ipp.pcap" -O ipp.pcap
wget "https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=x11-gtk.pcap.gz" -O x11-gtk.pcap.gz

mergecap --version > /dev/null 2>&1
if [ "$?" -eq 0 ]
then
	mergecap -w "x11-ipp.pcap" "ipp.pcap" "x11-gtk.pcap.gz" -F pcap
fi
