from pySRDF import *

pe = PEFile("upx.exe")

print "PE Overview:\n----------\n"
print "Magic : 0x%x" % pe.Magic
print "Subsystem : 0x%x" % pe.Subsystem
print "Imagebase : 0x%x" % pe.Imagebase
print "SizeOfImage : 0x%x" % pe.SizeOfImage
print "Entrypoint : 0x%x" % pe.Entrypoint
print "FileAlignment : 0x%x" % pe.FileAlignment
print "SectionAlignment : 0x%x" % pe.SectionAlignment

#Sections
print "\nPE Sections:\n----------\n"
for section in pe.Sections:
    print "Section Name: " + section.SectionName
    print "VirtualAddress : 0x%x" % section.VirtualAddress
    print "VirtualSize : 0x%x" % section.VirtualSize
    print "PointerToRawData : 0x%x" % section.PointerToRawData
    print "SizeOfRawData : 0x%x" % section.SizeOfRawData
    print "Characterisics : 0x%x" % section.Characterisics     #IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE
    print "RealAddr : 0x%x" % section.RealAddr
    print "\n"
		
#Import Table
print "\nImport Table:\n----------\n"
for DLL in pe.ImportTable:
    print "APIs of DLL: " + DLL.DLLName 
    for API in DLL.APIs:
        print "%s\t" % API.APIName
        #print "at 0x%x" % API.APIAddressPlace
    print "\n"       
#Export Table
print "\nExport Table:\n----------\n"
for Func in pe.ExportTable.Functions:
    print "API Name: " + Func.funcName
    print "Ordinal : 0x%x" % Func.funcOrdinal
    print "RVA : 0x%x" % Func.funcRVA
    
    
