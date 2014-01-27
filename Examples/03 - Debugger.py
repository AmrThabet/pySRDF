from pySRDF import *

dbg = Dbg("upx.exe")

#Setting Breakpoint
dbg.SetBp(dbg.PE.Entrypoint)
dbg.SetHardBp(0x401000,DBG_BYTE,DBG_CODE)       #Hardware Breakpoint on Execution size 1 byte (you have options: DBG_CODE, DBG_READWRITE and DBG_WRITE)
dbg.SetMemoryBp(0x401000,0x1000,DBG_WRITE)        #Size is multiplied by 0x1000
dbg.RemoveMemoryBp(0x401000)


#Execute Instructions
x = dbg.Step()
print dbg.GetLastError()                            #"The application stepped one step"
x = dbg.Run()
print dbg.GetLastError()                            #"Breakpoint reached"
x = dbg.Run()
print dbg.GetLastError()                            #"Hardware Breakpoint triggered"

'''
x Values:
DBG_STATUS_STEP     =>  4
DBG_STATUS_HARDWARE_BP   => 3
DBG_STATUS_MEM_BREAKPOINT  => 2
DBG_STATUS_BREAKPOINT => 1
DBG_STATUS_EXITPROCESS => 0
DBG_STATUS_ERROR => -1
DBG_STATUS_INTERNAL_ERROR => -2
DBG_STATUS_DIDNT_STARTED =>  -3
'''

#Getting Info
print "Imagebase 0x%x From Process" % dbg.Process.Imagebase     #you have access to process information from process object
print "Entrypoint 0x%x From PE" % dbg.PE.Entrypoint             #you have access to PE Information  from PEFile object

print "eax: %x" % dbg.eax                                       #or you can use dbg.GetReg(0) and update it using SetReg(0)
print "ecx: %x" % dbg.ecx
print "edx: %x" % dbg.edx
print "ebx: %x" % dbg.ebx
print "esp: %x" % dbg.esp
print "ebp: %x" % dbg.ebp
print "esi: %x" % dbg.esi
print "edi: %x" % dbg.edi
print "eip: %x" % dbg.eip
print "EFlags: %x" % dbg.EFlags
print "DebugStatus: %x" % dbg.DebugStatus                       #equal to Dr6 ..used forgetting which hardware breakpoint was hit
print "ProcessId: %x" % dbg.ProcessId
print "ThreadId: %x" % dbg.ThreadId
print "ExceptionCode: %x" % dbg.ExceptionCode


print "File Unpacked Successfully\n\nThe Disassembled Code\n----------------"

#Disassemble Instructions:
length = 0
for i in range(0,30):
    ins = dbg.disasm(dbg.eip + length)
    print "%x: %s" % (dbg.eip + length, ins.ins)
    length += ins.length
    




