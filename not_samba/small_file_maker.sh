#!/bin/sh

# Script to create lots of small files with xattrs for samba testing

target_num_files=100000
target_dir="/tmp/foo"
min_count=1  #minimum value for blocks in dd
max_count=5  #maximum value for blocks in dd
dd_bs=16384  #16KB
stream_name="DosStream.Afp_Resource"
i=1
mkdir $target_dir

while [ $i -le $target_num_files ]
do
        rnd_file=$(mktemp "$target_dir"/tmp.XXXXXXXX)
        dd_count=$(jot -r 1 $min_count $max_count)
        dd if=/dev/random of=$rnd_file count=$dd_count bs=$dd_bs
	dd if=/dev/random count=$dd_count bs=$dd_bs | setextattr -in "user" "$stream_name" $rnd_file
        i=$(($i + 1))
done
