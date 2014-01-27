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
