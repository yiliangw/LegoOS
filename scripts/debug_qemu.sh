#!/bin/bash

qemu-system-x86_64  \
	-kernel arch/x86/boot/bzImage -append "console=ttyS0 earlyprintk=serial,ttyS0,115200 memmap=2G\$4G" \
	-no-reboot \
	-cpu Haswell,+tsc,+sse,+xsave,+aes,+avx,+erms,+pdpe1gb \
	-m 4G -smp 8 \
	-display none \
	-serial stdio \
	-s -S
    # -d int,cpu_reset -D $OUTPUT_DIR/qemu.log \