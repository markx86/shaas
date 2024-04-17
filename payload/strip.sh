#!/bin/sh

set -ex

if test $# -lt 1; then
	echo "USAGE: $0 FILE"
	exit -1
fi

file=$1
tmp_file="/tmp/$file.tmp"

strip -s -R '!.load' "$file" -o "$tmp_file"
shstrtab_off=$(readelf -S "$tmp_file" | grep "\.shstrtab" | tr -s ' ' | cut -d ' ' -f7)
shstrtab_off=$(printf "%u" 0x$shstrtab_off)

head -c $shstrtab_off "$tmp_file" > "$file"
chmod +x "$file"
