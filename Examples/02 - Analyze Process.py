from pySRDF import *

#Change this line to your process Id
ProcessId   = 752


p = process(ProcessId)

print "Imagebase : 0x%x" % p.Imagebase
print "SizeOfImage : 0x%x" % p.SizeOfImage
print "Name : %s" % p.Name
print "Path : %s" % p.Path
print "MD5 : %s" % p.MD5
print "Pid : 0x%x" % p.Pid
print "PPid : 0x%x" % p.PPid
print "Commandline : %s" % p.Commandline
print "\n"
#Loaded Modules in the Memory
print "Loaded Modules\n---------\n"
for dll in p.ModuleList:
    print "Imagebase : 0x%x" % dll.Imagebase
    print "SizeOfImage : 0x%x" % dll.SizeOfImage
    print "Name : %s" % dll.Name
    print "Path : %s" % dll.Path
    print "MD5 : %s" % dll.MD5
    print "Number of Exported APIs : 0x%x" % dll.nExportedAPIs
    print "\n"
    
#Running Threads
print "Running Threads\n---------\n"
for thread in p.Threads:
    print "ThreadId : %d" % thread.ThreadId
    print "Eip : 0x%x" %  thread.Context.Eip
    print "TEB : 0x%x" %  thread.TEB
    print "StackBase : 0x%x" %  thread.StackBase
    print "StackLimit : 0x%x" %  thread.StackLimit
    print "SEH : 0x%x" %  thread.SEH;
    print "\n"
    
#Memory Map
print "Memory Map\n---------\n"
'''for Mem in p.MemoryMap:
    print "Address : 0x%x" % Mem.Address
    print "Size : 0x%x" % Mem.Size
    print "Protection : 0x%x" % Mem.Protection
    print "AllocationBase : 0x%x" % Mem.AllocationBase
    print "\n"
    '''
buff = p.Allocate(0,30)
p.Write(buff,"Hello from pySRDF",len("Hello from pySRDF"))
newbuff = p.Read(buff,30)

print newbuff

print "Testing Search in Process Memory .. it will take some time\n"
found = p.Search("pySRDF")                     #an example of memory search (it could take a normal string "xxx")

for item in found:
    print "Address: %x" % item.Address

