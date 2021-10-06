#!/bin/bash
for i in $(objdump -d bin/HandleKatzPIC.exe | grep "^ " | cut -f2); do echo -e -n "\x$i"; done >> bin/HandleKatz.bin
