#!/bin/bash
make -j8
qemu-system-x86_64  \
	-kernel arch/x86/boot/bzImage -append "console=ttyS0 earlyprintk=serial,ttyS0,115200 memmap=2G\$4G" \
	-cpu Skylake-Server \
	-m 4G -smp 4 \
	-serial stdio \
	-display none \
	-d int,cpu_reset -D ./qemu.log
