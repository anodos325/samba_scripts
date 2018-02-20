#!/bin/sh

# Script to create lots of small files with xattrs for samba testing
# Depends on openssl and winacl

target_num_files=100
target_num_dirs=1
target_dir="/mnt/flashyflashflash/SSD_SHARE/smb_small_files2"
min_count=200  #minimum value for blocks
max_count=700  #maximum value for blocks
bs=16384  #16KB
stream_name='DosStream.Afp_Resource:$DATA'
dosattrib_b64="MHgxMAAAAwADAAAAEQAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGKZfexKp9MBAAAAAAAAAAAK=="
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
            block_count=$(jot -r 1 $min_count $max_count)
            file_size=$(($block_count*$bs))
            openssl rand -out $rnd_file $file_size
            dd if=/dev/random count=1 bs=$bs status=none | \
                setextattr -in "user" "$stream_name" $rnd_file
            echo -n "$dosattrib_b64" | b64decode -r | \
                setextattr -i "user" "DOSATTRIB" $rnd_file
            file_iteration=$(($file_iteration + 1))
        done
dir_iteration=$(($dir_iteration + 1))
file_iteration=1
done

echo "setting default permissions on $target_dir"
winacl -a reset -O "$owner" -G "$group" -r -p "$target_dir"
