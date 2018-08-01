import pytest

from one_gadget import generate_one_gadget

x64_easy_case = {
        'libc/libc6_2.15-0ubuntu10_amd64.so': [0x441ed],
        'libc/libc6_2.19-0ubuntu6.14_amd64.so': [0x4647c, 0xe9415, 0xea36d],
        'libc/libc6_2.23-0ubuntu10_amd64.so': [0x4526a, 0xf02a4, 0xf1147],
        'libc/libc6_2.26-0ubuntu2.1_amd64.so': [0x47c9a, 0xfccde, 0xfdb8e],
        'libc/libc6_2.27-3ubuntu1_amd64.so': [0x4f322, 0x10a38c],
}

x64_hard_case = {
        'libc/libc6_2.15-0ubuntu10_amd64.so': [0x4418a, 0x441ed],
        'libc/libc6_2.19-0ubuntu6.14_amd64.so': [0x46428, 0x4647c, 0xe9415, 0xea36d],
        'libc/libc6_2.23-0ubuntu10_amd64.so': [0x45216, 0x4526a, 0xf02a4, 0xf1147],
        'libc/libc6_2.26-0ubuntu2.1_amd64.so': [0x47c46, 0x47c9a, 0xfccde, 0xfdb8e],
        'libc/libc6_2.27-3ubuntu1_amd64.so': [0x4f2c5, 0x4f322, 0x10a38c],
}

def test_x64_easy_case():
    for libc, value in x64_easy_case.items():
        for out, expected in zip(generate_one_gadget(libc), value):
            assert(out == expected)

def test_x64_hard_case():
    for libc, value in x64_hard_case.items():
        for out, expected in zip(generate_one_gadget(libc), value):
            assert(out == expected)
