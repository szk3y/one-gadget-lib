from capstone import *
from capstone.x86 import *
from elftools.elf.elffile import ELFFile
import sys


NUMBER_OF_CANDIDATES = 20
MAX_RSP_OFFSET = 0x200
ONE_GADGET_LIB_DEBUG = False


# add
# call
# jmp
# lea
# mov
# nop
# push
# sub
# xor
# movq
# movaps
# movhps


# Most practical gadgets have simple constraints.
# So I support only these instructions.
supported_instructions = [
    X86_INS_CALL,
    X86_INS_LEA,
    X86_INS_MOV,
]


def _get_environ_ptr(elffile):
    rela_dyn = elffile.get_section_by_name('.rela.dyn')
    if not rela_dyn:
        raise Exception('.rela.dyn section is not found')
    dynsym = elffile.get_section_by_name('.dynsym')
    if not dynsym:
        raise Exception('.dynsym section is not found')
    environ_addr = \
        [i['st_value'] for i in dynsym.get_symbol_by_name('environ')]
    environ_ptr = []
    for rel_entry in rela_dyn.iter_relocations():
        addr = dynsym.get_symbol(rel_entry.entry.r_info_sym)['st_value']
        if addr in environ_addr:
            environ_ptr.append(rel_entry.entry['r_offset'])
    return environ_ptr


def _get_execve_offset(elffile):
    dynsym_sec = elffile.get_section_by_name('.dynsym')
    if not dynsym_sec:
        raise Exception('.dynsym section is not found')
    sym_list = dynsym_sec.get_symbol_by_name('execve')
    for sym in sym_list:  # sym_list contains only one item
        return sym['st_value']


def _load_code(elffile):
    '''
    This function extracts code from an ELF file.
    '''
    text_section = elffile.get_section_by_name('.text')
    if not text_section:
        raise Exception('.text section is not found')
    return text_section.data()


def _get_code_offset(elffile):
    '''
    This function returns an offset to .text section
    '''
    text_section = elffile.get_section_by_name('.text')
    if not text_section:
        raise Exception('.text section is not found')
    return text_section['sh_addr']


def _binsh_offset(fobj):
    '''
    This function finds "/bin/sh" in the file and returns its offset.
    '''
    data = fobj.read()
    return data.find(b'/bin/sh\x00')


def _is_binsh_assignment(instruction, binsh):
    '''
    If a given instruction assigns "/bin/sh" to rdi,
    this function returns True.
    Note: I assume that all "/bin/sh" assignments
    look like "lea rdi, [rip+<offset>]".
    '''
    # check whether this instruction is lea or not
    if instruction.id != X86_INS_LEA:
        return False

    # check op_str looks like 'rdi, [rip+<offset>]'
    if instruction.op_str != 'rdi, [rip + 0x%x]' % \
            (binsh - instruction.address - instruction.size):
        return False

    return True


def _has_execve_before_rdi_changes(instruction_list, begin, execve_addr):
    '''
    Determine that the potential gadget calls execve before rdi changes.
    '''
    for instruction in instruction_list[begin+1:]:  # skip rdi = "/bin/sh";
        if instruction.id == X86_INS_CALL:
            # 'call execve' is the end of the block
            if hex(execve_addr) == instruction.op_str:
                return True
            # other call instructions may change rdi
            else:
                return False
        # When rdi is in the destination operand, it will be changed
        elif instruction.op_str.startswith('rdi'):
            return False
        # FIXME: jmp should be avoided


def _linear_search_execve(instruction_list, begin, execve_addr):
    '''
    Returns the address of the instruction
    below the first 'call execve'.
    '''
    prev_instruction = None
    for instruction in instruction_list[begin:]:
        if prev_instruction is not None and \
                prev_instruction.id == X86_INS_CALL and \
                prev_instruction.op_str == hex(execve_addr):
            return instruction.address
        prev_instruction = instruction


class ValueX64:
    base = None
    offset = None

    def __init__(self, _base, _offset):
        self.base = _base
        self.offset = _offset


class ReferenceX64:
    base = None
    offset = None

    def __init__(self, _base, _offset):
        self.base = _base
        self.offset = _offset


regname = {
    None: 'None',
    X86_REG_RAX: 'RAX',
    X86_REG_RCX: 'RCX',
    X86_REG_RDX: 'RDX',
    X86_REG_RBX: 'RBX',
    X86_REG_RSP: 'RSP',
    X86_REG_RBP: 'RBP',
    X86_REG_RSI: 'RSI',
    X86_REG_RDI: 'RDI',
    X86_REG_R8:  'R8',
    X86_REG_R9:  'R9',
    X86_REG_R10: 'R10',
    X86_REG_R11: 'R11',
    X86_REG_R12: 'R12',
    X86_REG_R13: 'R13',
    X86_REG_R14: 'R14',
    X86_REG_R15: 'R15',
}


class CpuStateX64:
    def __init__(self):
        self.reg = [None for i in range(X86_REG_ENDING)]
        self.stack = [None for i in range(MAX_RSP_OFFSET)]
        self.reg[X86_REG_RSP] = ValueX64(None, None)

    def info(self):
        for i, r in enumerate(self.reg):
            if not r:
                continue
            print('{} {} {} {}'.format(
                    regname[i], type(r), regname[r.base], r.offset))

    def register_is_filled(self, reg):
        if reg is None:
            return False
        if reg.base is None:
            return True
        return self.register_is_filled(self.reg[reg.base])

    def is_filled(self):
        return self.register_is_filled(self.reg[X86_REG_RDI]) and \
               self.register_is_filled(self.reg[X86_REG_RSI]) and \
               self.register_is_filled(self.reg[X86_REG_RDX])

    def constraints(self):
        assert(self.reg[X86_REG_RSI].base == X86_REG_RSP)
        return '[rsp + {}] == 0'.format(hex(self.reg[X86_REG_RSI].offset))


def _is_call_execve(instruction, execve_addr):
    return instruction.id == X86_INS_CALL and \
            hex(execve_addr) == instruction.op_str


def _is_one_gadget(cpu, binsh, environ_ptr):
    # RDI == "/bin/sh"
    if not isinstance(cpu.reg[X86_REG_RDI], ValueX64) or \
            cpu.reg[X86_REG_RDI].base is not None or \
            cpu.reg[X86_REG_RDI].offset != binsh:
        return False
    # RSI == [RSP+0xXX]
    if isinstance(cpu.reg[X86_REG_RSI], ValueX64) and \
            cpu.reg[X86_REG_RSI].base != X86_REG_RSP:
        return False
    # RDX == [RAX] and RAX == [environ_ptr]
    if not isinstance(cpu.reg[X86_REG_RDX], ReferenceX64) or \
            cpu.reg[X86_REG_RDX].base != X86_REG_RAX or \
            cpu.reg[X86_REG_RDX].offset != 0:
        return False
    if not isinstance(cpu.reg[X86_REG_RAX], ReferenceX64) or \
            cpu.reg[X86_REG_RAX].base is not None or \
            cpu.reg[X86_REG_RAX].offset not in environ_ptr:
        return False
    return True


def _is_complex_instruction(instruction):
    if instruction.id == X86_INS_LEA:
        if instruction.operands[0].type != X86_OP_REG:
            return True
        return False
    elif instruction.id == X86_INS_MOV:
        return False
    else:  # unsupported instructions
        return True


def _has_complex_instructions(instruction_list, begin, execve_addr):
    index = begin
    instruction = instruction_list[index]
    while not _is_call_execve(instruction, execve_addr):
        if _is_complex_instruction(instruction):
            return True
        index = index + 1
        instruction = instruction_list[index]
    return False


def _execute_instructions_before_binsh(cpu, instruction_list, begin):
    '''
    Repeatedly check a previous instruction until
    all argument registers(rdi, rsi, rdx) are filled.
    Index of one-gadget is returned.
    '''
    index = begin - 1
    instruction = instruction_list[index]
    while not cpu.is_filled():
        if instruction.id == X86_INS_LEA:
            assert(len(instruction.operands) == 2)
            assert(instruction.operands[0].type == X86_OP_REG)
            assert(instruction.operands[1].type == X86_OP_MEM)
            dst = instruction.operands[0].reg
            base = instruction.operands[1].mem.base
            offset = instruction.operands[1].mem.disp
            if base == X86_REG_RIP:
                base = None
                offset = offset + instruction.address + instruction.size
            cpu.reg[dst] = ValueX64(base, offset)
        elif instruction.id == X86_INS_MOV:
            assert(len(instruction.operands) == 2)
            if instruction.operands[0].type == X86_OP_REG:
                dst = instruction.operands[0].reg
            elif instruction.operands[0].type == X86_OP_MEM:
                pass
            else:
                if ONE_GADGET_LIB_DEBUG:
                    raise Exception('Unsupported mov instruction')
                else:
                    break
            if instruction.operands[1].type == X86_OP_REG:
                src = instruction.operands[0].reg
                cpu.reg[dst] = ValueX64(src, 0)
            elif instruction.operands[1].type == X86_OP_MEM:
                base = instruction.operands[1].mem.base
                if cpu.register_is_filled(cpu.reg[base]):
                    if ONE_GADGET_LIB_DEBUG:
                        raise Exception('Unsupported mov instruction')
                    else:
                        break
                offset = instruction.operands[1].mem.disp
                if base == X86_REG_RIP:
                    base = None
                    offset = offset + instruction.address + instruction.size
                cpu.reg[dst] = ReferenceX64(base, offset)
        else:
            if ONE_GADGET_LIB_DEBUG:
                _print_instruction(instruction)
                cpu.info()
                raise Exception('Unsupported instruction found')
            else:
                break
        index = index - 1
        instruction = instruction_list[index]
    return index + 1  # index of one-gadget


def _execute_instructions_between_binsh_and_execve(
        cpu, instruction_list, begin, execve_addr):
    '''
    According to my analysis, most one-gadgets use only lea and mov.
    So this code ignore candidates that have other instructions.
    '''
    index = begin
    instruction = instruction_list[index]
    # repeat until execve is called
    while not _is_call_execve(instruction, execve_addr):
        if instruction.id == X86_INS_LEA:
            assert(len(instruction.operands) == 2)
            assert(instruction.operands[0].type == X86_OP_REG)
            assert(instruction.operands[1].type == X86_OP_MEM)
            dst = instruction.operands[0].reg
            base = instruction.operands[1].mem.base
            offset = instruction.operands[1].mem.disp
            if base == X86_REG_RIP:
                base = None
                offset = offset + instruction.address + instruction.size
            cpu.reg[dst] = ValueX64(base, offset)
        elif instruction.id == X86_INS_MOV:
            assert(len(instruction.operands) == 2)
            # first operand
            if instruction.operands[0].type == X86_OP_REG:
                dst = instruction.operands[0].reg
            elif instruction.operands[0].type == X86_OP_MEM:
                pass  # ignore mov to memory
            else:
                if ONE_GADGET_LIB_DEBUG:
                    raise Exception('Unsupported mov instruction')
                else:
                    break
            # second operand and assignment
            if instruction.operands[1].type == X86_OP_REG:
                src = instruction.operands[1].reg
                cpu.reg[dst] = ValueX64(src, 0)
            elif instruction.operands[1].type == X86_OP_MEM:
                base = instruction.operands[1].mem.base
                offset = instruction.operands[1].mem.disp
                if base == X86_REG_RIP:
                    offest = offset + instruction.address + instruction.size
                    base = None
                cpu.reg[dst] = ReferenceX64(base, offset)
        else:
            if ONE_GADGET_LIB_DEBUG:
                _print_instruction(instruction)
                raise Exception('Unknown instruction found')
            break
        index = index + 1
        instruction = instruction_list[index]


def _generate_one_gadget(code, offset, binsh, execve_addr, environ_ptr):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.syntax = CS_OPT_SYNTAX_INTEL
    md.detail = False
    instruction_list = list(md.disasm(code, offset))

    for i, instruction in enumerate(instruction_list):
        if not _is_binsh_assignment(instruction, binsh):
            continue
        if not _has_execve_before_rdi_changes(
                instruction_list, i, execve_addr):
            continue

        # more detailed disassembly
        first_addr = instruction_list[i-NUMBER_OF_CANDIDATES].address
        last_addr = \
            _linear_search_execve(instruction_list, i, execve_addr)
        md.detail = True
        detailed_instruction_list = list(
            md.disasm(code[first_addr-offset:last_addr-offset], first_addr))

        if _has_complex_instructions(
                detailed_instruction_list, NUMBER_OF_CANDIDATES, execve_addr):
            continue

        cpu = CpuStateX64()  # TODO: replace with unicorn emulator
        _execute_instructions_between_binsh_and_execve(
            cpu, detailed_instruction_list, NUMBER_OF_CANDIDATES, execve_addr)
        one_gadget_index = _execute_instructions_before_binsh(
            cpu, detailed_instruction_list, NUMBER_OF_CANDIDATES)
        if not _is_one_gadget(cpu, binsh, environ_ptr):
            continue
        yield (detailed_instruction_list[one_gadget_index], cpu.constraints())


def _print_instruction_list(ilist):
    for i in ilist:
        _print_instruction(i)


def _print_instruction(i):
    print('0x%x:\t%s\t%s' % (i.address, i.mnemonic, i.op_str))


def generate_one_gadget_full(filename):
    '''
    This is the main function of this library, which
    computes offset to one-gadget and constraints we have to satisfy.
    A tuple of instruction and constraints is returned as an iterator.
    '''
    known_constraints = []
    with open(filename, 'rb') as f:
        binsh = _binsh_offset(f)
        elffile = ELFFile(f)
        code = _load_code(elffile)
        offset = _get_code_offset(elffile)
        execve_addr = _get_execve_offset(elffile)
        environ_ptr = _get_environ_ptr(elffile)
    for instruction, constraints in \
            _generate_one_gadget(
            code, offset, binsh, execve_addr, environ_ptr):
        if constraints in known_constraints:
            continue
        known_constraints.append(constraints)
        yield instruction, constraints


def generate_one_gadget(filename):
    '''
    This function yields offset to one-gadget.
    '''
    for istruction, constraint in generate_one_gadget_full(filename):
        yield istruction.address


if __name__ == '__main__':
    if len(sys.argv) == 2:
        libc = sys.argv[1]
    else:
        libc = '/lib/x86_64-linux-gnu/libc.so.6'
    for instruction, constraint in generate_one_gadget_full(libc):
        _print_instruction(instruction)
        print(constraint)
