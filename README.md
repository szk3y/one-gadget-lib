# one-gadget-lib
[![Build Status](https://travis-ci.org/szk3y/one-gadget-lib.svg?branch=master)](https://travis-ci.org/szk3y/one-gadget-lib)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

One-gadget is code that invokes "/bin/sh" without any arguments, so all you need is jump to its address.
This library provides the function to find offset to one-gadget in libc.

One-gadget-lib works with both python2 and python3.

## Requirements
- capstone
- pyelftools

You can install these requrements by typing following commands.

```bash
pip3 install capstone pyelftools
```

or

```bash
pip install capstone pyelftools
```

## Usage

```python
from one_gadget import generate_one_gadget

path_to_libc = '/lib/x86_64-linux-gnu/libc.so.6'

for i in generate_one_gadget(path_to_libc):
    print(i)
```

Also, you can use it from your shell.

```bash
python ./one_gadget.py /lib/x86_64-linux-gnu/libc.so.6
```

## Future work
- Support ARM
- Support complex case like this:
```
   45216:       48 8d 35 43 13 38 00    lea    rsi,[rip+0x381343]        # 3c6560 <__abort_msg@@GLIBC_PRIVATE+0x980>
   4521d:       31 d2                   xor    edx,edx
   4521f:       bf 02 00 00 00          mov    edi,0x2
   45224:       48 89 5c 24 40          mov    QWORD PTR [rsp+0x40],rbx
   45229:       48 c7 44 24 48 00 00    mov    QWORD PTR [rsp+0x48],0x0
   45230:       00 00
   45232:       48 89 44 24 30          mov    QWORD PTR [rsp+0x30],rax
   45237:       48 8d 05 16 7b 14 00    lea    rax,[rip+0x147b16]        # 18cd54 <_libc_intl_domainname@@GLIBC_2.2.5+0x194>
   4523e:       48 89 44 24 38          mov    QWORD PTR [rsp+0x38],rax
   45243:       e8 a8 04 ff ff          call   356f0 <__sigaction@@GLIBC_2.2.5>
   45248:       48 8d 35 71 12 38 00    lea    rsi,[rip+0x381271]        # 3c64c0 <__abort_msg@@GLIBC_PRIVATE+0x8e0>
   4524f:       31 d2                   xor    edx,edx
   45251:       bf 03 00 00 00          mov    edi,0x3
   45256:       e8 95 04 ff ff          call   356f0 <__sigaction@@GLIBC_2.2.5>
   4525b:       31 d2                   xor    edx,edx
   4525d:       4c 89 e6                mov    rsi,r12
   45260:       bf 02 00 00 00          mov    edi,0x2
   45265:       e8 b6 04 ff ff          call   35720 <sigprocmask@@GLIBC_2.2.5>
   4526a:       48 8b 05 47 ec 37 00    mov    rax,QWORD PTR [rip+0x37ec47]        # 3c3eb8 <_IO_file_jumps@@GLIBC_2.2.5+0x7d8>
   45271:       48 8d 3d df 7a 14 00    lea    rdi,[rip+0x147adf]        # 18cd57 <_libc_intl_domainname@@GLIBC_2.2.5+0x197>
   45278:       48 8d 74 24 30          lea    rsi,[rsp+0x30]
   4527d:       c7 05 19 12 38 00 00    mov    DWORD PTR [rip+0x381219],0x0        # 3c64a0 <__abort_msg@@GLIBC_PRIVATE+0x8c0>
   45284:       00 00 00
   45287:       c7 05 13 12 38 00 00    mov    DWORD PTR [rip+0x381213],0x0        # 3c64a4 <__abort_msg@@GLIBC_PRIVATE+0x8c4>
   4528e:       00 00 00
   45291:       48 8b 10                mov    rdx,QWORD PTR [rax]
   45294:       e8 d7 74 08 00          call   cc770 <execve@@GLIBC_2.2.5>

```

## Reference
- [one_gadget](https://github.com/david942j/one_gadget)
- [The one-gadget in glibc](https://david942j.blogspot.com/2017/02/project-one-gadget-in-glibc.html) (blog post by the author of [one_gadget](https://github.com/david942j/one_gadget))
