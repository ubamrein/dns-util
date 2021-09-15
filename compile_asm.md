<!--
 Copyright (c) 2021 Patrick Amrein <amrein@ubique.ch>
 
 This software is released under the MIT License.
 https://opensource.org/licenses/MIT
-->

 Compile: 
> as shell.s -o hello.o

Link: 
> ld -L/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib -lSystem hello.o -e _main -o hello  

Extract Shell code:
> for i in $(objdump -d ./hello | grep ": " | cut -f2 -d : | cut -f1);do echo -n $i; done; echo

Base64 encode it:
> echo -n <shellcode> | xxd -r -p | base64encode 