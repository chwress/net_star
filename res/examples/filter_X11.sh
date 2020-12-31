#!/bin/bash
my_dir=$(cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd)

bin="$( readlink -f "$my_dir/../../bin" )"

input_dir=$( readlink -f "$1" )

if [ -z "$input_dir" ]
then
	echo "[!] Please provide the input directory to process"
	exit
fi

pcaps=($( find "$input_dir" -maxdepth 1 -name "*.dump*" -or -name "*.cap" -or -name "*.pcap" | sort ))
if [ -f "$input_dir" ]
then
	input_dir=$( dirname "$input_dir" )
fi

parallel --bar "$bin/net_filter" packets {1} "\;X11\;" --excl ::: ${pcaps[@]}
#parallel --bar "$bin/net_filter" packets {1} "\;6000\;" --excl ::: ${pcaps[@]}
