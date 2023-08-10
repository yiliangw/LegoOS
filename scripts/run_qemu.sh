#!/bin/bash

_debug=0
_log=0

while getopts ":dl:" opt; do
	case $opt in
		d)
			_debug=1
			;;
		l)
			_log=1
			_log_file=$OPTARG
			;;
		\?)
			echo "Invalid option: -$OPTARG" >&2
			exit 1
			;;
		:)
			echo "Option -$OPTARG requires an argument." >&2
			exit 1
			;;
	esac
done

make -j$(($(nproc)-2))

_cmd=$(cat <<EOF
qemu-system-x86_64  \
	-kernel arch/x86/boot/bzImage -append "console=ttyS0 earlyprintk=serial,ttyS0,115200 memmap=2G\$4G" \
	-cpu Skylake-Server \
	-m 8G -smp 4 \
	-serial stdio \
	-display none
EOF
)

if [[ $_debug -eq 1 ]]; then
	_cmd="$_cmd -S -s"
fi

if [[ $_log -eq 1 ]]; then
	_cmd="$_cmd -D $_log_file"
fi

eval $_cmd

