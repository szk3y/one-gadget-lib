#!/usr/bin/env python3

# TODO: check constraints before and after the assignments

from capstone import *
from capstone.x86 import *
from elftools.elf.elffile import ELFFile

# All practical gadgets have simple constraints.
# So I support only these instructions.
supported_instructions = [
    X86_INS_ADD,
    X86_INS_CALL,
    X86_INS_JMP,
    X86_INS_LEA,
    X86_INS_MOV,
    X86_INS_NOP,
    X86_INS_PUSH,
    X86_INS_SUB,
    #X86_INS_SYSCALL,
    X86_INS_XOR,
]

def _get_execve_offset(filename):
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)
        dynsym_sec = elffile.get_section_by_name('.dynsym')
        if not dynsym_sec:
            raise Exception('.dynsym section is not found')
        sym_list = dynsym_sec.get_symbol_by_name('execve')
        for sym in sym_list: # sym_list contains only one item
            return sym['st_value']

def _load_code(filename):
    '''
    This function extracts code from an ELF file.
    '''
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)
        text_section = elffile.get_section_by_name('.text')
        if not text_section:
            raise Exception('.text section is not found')
        return text_section.data()

def _get_code_offset(filename):
    '''
    This function returns an offset to .text section
    '''
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)
        text_section = elffile.get_section_by_name('.text')
        if not text_section:
            raise Exception('.text section is not found')
        return text_section['sh_addr']

def _binsh_offset(filename):
    '''
    This function finds "/bin/sh" in the file and returns its offset.
    '''
    with open(filename, 'rb') as f:
        data = f.read()
    return data.find(b'/bin/sh\x00')

def _has_binsh_assignment(inst, binsh):
    '''
    If a given instruction assigns "/bin/sh" to rdi,
    this function returns True.
    Note: I assume that assignments look like "lea rdi, [rip+<offset>]"
    '''
    # check whether this instruction is lea or not
    if inst.id != X86_INS_LEA:
        return False

    if len(inst.operands) != 2: # must be True
        raise Exception("Invalid lea instruction")
    operand0 = inst.operands[0]
    operand1 = inst.operands[1]

    # check the first operand
    if operand0.type != X86_OP_REG or operand0.reg != X86_REG_RDI:
        return False

    # check the second operand
    if operand1.type != X86_OP_MEM:
        return False
    if operand1.mem.base == 0:
        return False
    if operand1.mem.disp == 0:
        return False
    if operand1.mem.base != X86_REG_RIP:
        return False
    if inst.size + inst.address + operand1.mem.disp != binsh:
        return False

    return True

def _has_execve_before_rdi_changes(inst_list, begin, jmp_addr_table, execve_addr):
    '''
    Determine that the potential gadget calls execve before rdi changes.
    '''
    index = begin+1 # skip rdi = "/bin/sh";
    while True:
        inst = inst_list[index]
        if inst.id == X86_INS_JMP:
            operand = inst.operands[0]
            next_addr = operand.imm
            index = jmp_addr_table[next_addr]
        elif inst.id == X86_INS_CALL: # call must be execve
            operand = inst.operands[0]
            if operand.type != X86_OP_IMM:
                return False
            if operand.imm == execve_addr:
                return True
            else:
                return False
        elif inst.id in supported_instructions:
            # check that rdi is modified
            if len(inst.operands) == 2 and \
                    inst.operands[0].type == X86_OP_REG and \
                    inst.operands[0].reg == X86_REG_RDI:
                return False
            index = index + 1
        else: # unsupported instructions
            return False

def _generate_one_gadget(code, offset, binsh, execve_addr):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.syntax = CS_OPT_SYNTAX_INTEL
    md.detail = True
    instruction_list = list(md.disasm(code, offset))

    # build a table to convert address to index
    jmp_addr_table = {}
    for i, inst in enumerate(instruction_list):
        jmp_addr_table[inst.address] = i

    for i, inst in enumerate(instruction_list):
        if _has_binsh_assignment(inst, binsh) and \
                _has_execve_before_rdi_changes(
                instruction_list, i, jmp_addr_table, execve_addr):
            yield inst

def _print_instruction(i):
    print('0x%x:\t%s\t%s' % (i.address, i.mnemonic, i.op_str))

def generate_one_gadget(filename):
    '''
    This is the main function of this library,
    which computes offsets to one-gadget and returns them as iterators.
    '''
    # TODO: integrate file open
    code   = _load_code(filename)
    offset = _get_code_offset(filename)
    binsh  = _binsh_offset(filename)
    execve_addr = _get_execve_offset(filename)
    for i in _generate_one_gadget(code, offset, binsh, execve_addr):
        yield i

if __name__ == '__main__':
    #default_libc = '/lib/x86_64-linux-gnu/libc.so.6'
    default_libc = './libc.so.6'
    for i in generate_one_gadget(default_libc):
        _print_instruction(i)
