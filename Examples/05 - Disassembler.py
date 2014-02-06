from pySRDF import *

#write any instruction there .. in the same format
INSTRUCTION = "mov eax, dword ptr [esp + 10h ]"

dis = Disasm()

instr = dis.assemble(INSTRUCTION)
ins = dis.disasm(instr)

print "-*-*-*-*- Disassembling Instruction : " + ins.ins + " -*-*-*-*-"

if ins.flags & NO_SRCDEST:
    print "Shape : op"
elif ins.flags & SRC_NOSRC:
    print "Shape : op dest"
else:
    print "Shape : op dest, src"

print "Opcode : " +  ins.cmd 

if ins.flags & DEST_RM:
    print "DEST : dword ptr [modrm]\nThe ModRM : "
    
    for i in range(0,ins.modrm.length):
        print "The Item No.%d:" % i,
        
        if ins.modrm.flags(i) & RM_REG:
            print "Register ",
            if ins.modrm.flags(i) & RM_MUL2:
                print "Multiplied (*) by 2 ",
            if ins.modrm.flags(i) & RM_MUL4:
                print "Multiplied (*) by 4 ",
            if ins.modrm.flags(i) & RM_MUL8:
                print "Multiplied (*) by 8 ",
            print "and the Register is No. %d" % ins.modrm.items(i)
            
        elif ins.modrm.flags(i) & RM_DISP:
            if ins.modrm.flags(i) & RM_DISP8:
               print "Displacement with Size 1 byte and the displacement is equal to 0x%x" %ins.modrm.items(i)
            if ins.modrm.flags(i) & RM_DISP16:
                print "Displacement with Size 2 bytes and the displacement is equal to 0x%x" %ins.modrm.items(i)
            if ins.modrm.flags(i) & RM_DISP32:
                print "Displacement with Size 4 bytes and the displacement is equal to 0x%x" %ins.modrm.items(i)

elif ins.flags & DEST_REG:
    print "DEST : Register and its No. %d" % ins.dest

else: 
    print "DEST : Immediate and equal to %d" % ins.dest

if not ins.flags & SRC_NOSRC:
    if ins.flags & SRC_RM:
        print "SRC : dword ptr [modrm]\nThe ModRM : "
        
        for i in range(0,ins.modrm.length):
            print "The Item No. %d: " % i,
            if ins.modrm.flags(i) & RM_REG:
                print "Register ",
                if ins.modrm.flags(i) & RM_MUL2: 
                    print "Multiplied (*) by 2 ",
                if ins.modrm.flags(i) & RM_MUL4: 
                    print "Multiplied (*) by 4 ",
                if ins.modrm.flags(i) & RM_MUL8: 
                    print "Multiplied (*) by 8 ",
                    
                print "and the Register is No. %d" % ins.modrm.items(i) 
                
            elif ins.modrm.flags(i) & RM_DISP:
            
                if ins.modrm.flags(i) & RM_DISP8:
                    print "Displacement with Size 1 byte and the displacement is equal to 0x%x" % ins.modrm.items(i)
                if ins.modrm.flags(i) & RM_DISP16:
                    print "Displacement with Size 2 bytes and the displacement is equal to 0x%x" % ins.modrm.items(i)
                if ins.modrm.flags(i) & RM_DISP32:
                    print "Displacement with Size 4 bytes and the displacement is equal to 0x%x" % ins.modrm.items(i)

    elif ins.flags & SRC_REG:
        print "SRC : Register and its No. %d " % ins.src
    else:
         print "SRC : Immediate and equal to " % ins.nsrc

#The Instruction Category:

print ins.category

'''
Should the result become one of:


OP_TYPE_I386 => 0x00000001
OP_TYPE_FPU => 0x00000002
OP_TYPE_MMX => 0x00000004
OP_TYPE_SSE => 0x00000008


OP_TYPE_ARTHIMETIC1 => 0x00000010                add,sub,xor,or,shl,shr,and,ror,rol and the same for fpu,mmx
OP_TYPE_ARTHIMETIC2 => 0x00000020                mul,div ...
OP_TYPE_ARTHIMETIC3 => 0x00000040                all complex fpu mathimatics
OP_TYPE_FLOW_REDIRECTION => 0x00000080           like call,jmp,jcc, ...
OP_TYPE_FLAG_TEST => 0x000000C0                  cmp,test, or ... 
OP_TYPE_PRIVILEDGE => 0x00000100                 like in,out ...
OP_TYPE_DATA_MANIPULATE => 0x00000200            movs, lods,stos,xchg, lea ... (not included xadd)
OP_TYPE_FLAG_MANIPULATE => 0x00000400            like cli,sti ...
OP_TYPE_NOP  => 0x00000800                       nop instructions
OP_TYPE_ARTIMITIC1_FLAGS => 0x00000C10           it's a part of Arthimitic 1 and it's like adc ...
OP_TYPE_UNKNOWN_BEHAVIOR => 0x00001000           like jp, aad,daa ... 
OP_TYPE_STACK_MANIPULATE  => 0x00002000          like push, pop ..
'''