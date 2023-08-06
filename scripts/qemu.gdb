target remote localhost:1234

# 1. startup_64
b *0x1000000

# 2. detect whether the kernel is reclocated
b *0x100000e

# 3. check the change of %rax (%cr3)
b *0x100020c
b *0x100020f
b *0x1000216

c

# 1
c

# 2
i r rbp
c

# 3
i r rax
c
i r rax
c
i r rax