from pySRDF import *

emu = Emulator("upx.exe")           # or it can take the shellcode giving the array of bytes like Emulator("\x50\x30",len("\x50\x30"))

#Getting Info:
print "eax: %x" % emu.eax               # or you can use GetReg(index) and SetReg(index)
print "ecx: %x" % emu.ecx
print "edx: %x" % emu.edx
print "ebx: %x" % emu.ebx
print "esp: %x" % emu.esp
print "ebp: %x" % emu.ebp
print "esi: %x" % emu.esi
print "edi: %x" % emu.edi
print "eip: %x" % emu.eip
print "EFlags: %x" % emu.EFlags


print "Imagebase: %x" % emu.Imagebase

#Setting Breakpoint:

x = emu.SetBp("__isdirty(eip)")              #which set bp on Execute on modified data ... emu.RemoveBp(x) to remove it

'''
Other Examples:
--------------
__isapi():                    break on any API
__isapiequal(APIName):        break on any API
eip == 0x401000:              break on specfic Eip
(__read(eip) & 0xff) == 0xcc: break when the next instruction is int3 (0xCC)
__lastmodified(0) > 0x00401000: break on last modified byte > 0x00401000
'''

#Executing the Code
emu.Step()
emu.MaxIteration = 1000000  # you can set maximum iterations (instructions) to emulate (default 1 million)
emu.Run()                   # OR emu.Run("ins.log") to log all running instructions including the registers for debugging
print emu.GetLastError()


#Reading the Memory

print "Memory Map:\n----------"
for mem in emu.GetMemoryPage():
    print "VirtualAddr: %x" % mem.VirtualAddr
    print "RealAddr: %x" % mem.RealAddr
    print "Size: %x" % mem.Size
    print "Flags: %x" % mem.Flags
    print "\n"

print "Modified Memory:\n----------"
for mem in emu.GetDirtyPages():
    print "VirtualAddr: %x" % mem.vAddr
    print "Size: %x" % mem.Size
    print "Flags: %x" % mem.Flags
    print "\n"

emu.ClearDirtyPages()              #clear all modified pages (this function doesn't reset the values of these pages but reset the dirty/modifed mark)

print "VirtualAddr of eip Page: %x" % emu.GetMemoryPageByVA(emu.eip).VirtualAddr
print "RealAddr of eip: %x" % emu.GetRealAddr(emu.eip)


#Disassemble Instructions
print "File Unpacked Successfully\n\nThe Disassembled Code\n----------------"

length = 0
for i in range(0,30):
    ins = emu.disasm(emu.eip + length)
    print "%x: %s" % (emu.eip + length, ins.ins)
    length += ins.length


print emu.Read(emu.eip,30)
#emu.Write(0x401000,"\x50\x40",len("\x50\x40"))

#Dump File
emu.Dump("upx_unpacked.exe",DUMP_FIXIMPORTTABLE)        #DUMP_FIXIMPORTTABLE create new import table for new APIs that was get by GetProcAddress ... other options are DUMP_ZEROIMPORTTABLE and DUMP_UNLOADIMPORTTABLE

found = emu.Search("{CC:CC:CC:CC}")                     #an example of memory search (it could take a normal string "xxx")

for item in found:
    print "Address: %x" % item.Address

