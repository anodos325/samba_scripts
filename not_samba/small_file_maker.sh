#!/bin/sh

# Script to create lots of small files with xattrs for samba testing
# Depends on openssl and winacl

target_num_files=10
target_num_dirs=10
target_dir="/mnt/dozer/smb_small_files2"
min_count=1  #minimum value for blocks in dd
max_count=5  #maximum value for blocks in dd
dd_bs=16384  #16KB
stream_name='DosStream.Afp_Resource:$DATA'
dosattrib_b64='CTB4MTAAAAMAAwAAABEAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABimX3sSqfTAQAAAAAAAAAACg=='
owner="root"
group="wheel"

file_iteration=1
dir_iteration=1
mkdir -p $target_dir

while [ $dir_iteration -le $target_num_dirs ]
do
rnd_dir=$(mktemp -d "$target_dir"/smbtestdir.XXXXX)
echo "$rnd_dir"
        while [ $file_iteration -le $target_num_files ]
        do
            rnd_file=$(mktemp "$rnd_dir"/smbtest.XXXXXXXX)
            dd_count=$(jot -r 1 $min_count $max_count)
            dd if=/dev/zero count=$dd_count bs=$dd_bs status=none | \
                openssl enc -aes-256-ecb -k abcd123456 | dd of=$rnd_file
            dd if=/dev/zero count=$dd_count bs=$dd_bs status=none | \
                openssl enc -aes-256-ecb -k abcd123456 | \
                setextattr -in "user" "$stream_name" $rnd_file
            echo "$dosattrib_b64" | b64decode -r | \ 
                setextattr -i "user" "DOSATTRIB" $rnd_file
            file_iteration=$(($file_iteration + 1))
        done
dir_iteration=$(($dir_iteration + 1))
file_iteration=1
done

echo "setting default permissions on $target_dir"
winacl -a reset -O "$owner" -G "$group" -r -p "$target_dir"
