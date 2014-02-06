kfrom pySRDF import *

yara = YaraScanner()

yara.AddRule("UPX")
yara.AddRule("{CC:CC:CC:CC}")

f = open("upx.exe")
text = f.read()

results = yara.Search(f,len(f))

for result in results:
    print "RuleName: %s" % result.Name
    print "Offset: 0x%x" % result.Offset    #offset is the distance between the beginning of the text and the found matched string

print ssdeep(f,len(f))                      #you can use ssdeepcompare(signature1,signature2)
print md5(f,len(f))

