========================================================================
    pySRDF Project Overview
========================================================================

Overview:
---------

This Project is a the python implementation for The Security Research 
and Development Framework

This Project includes:

1. PE Parser
2. Process analyzer, DLL Injector
3. Debugger 
4. x86 Emulator for binary files and shellcodes

That's the strongest reverse engineering and malware analysis tool for
python and the easiest to install and use

The application still in the pre-stage and BETA !! ... it's still in the 
beginning

The Binary Files are:
---------------------
1. _pySRDF.pyd
2. pySRDF.py
3. SRDF.dll
4. X86 Emulator.dll
5. sqlite3.dll

the project works only on Python version 2.7 win32 ... which works on both
win32 and win64

Examples:
---------
>>from pySRDF import *

>>dbg = Dbg("C:\\test.exe")

>>dbg.SetBp(0x401000)
>>dbg.Run()

OR Using the Emulator:

>> emu = Emulator("C:\\test.exe")
>> emu.SetBp("eip == 0x401000")
>> emu.Run()

OR

>> emu.SetBp("__isdirty(eip)") #which set bp on Execute on modified data 
>> emu.Run()									 #used for packed files and encrypted malware

Source Code:
------------

To make the project compiled successfully ... you must clone winSRDF beside it 
and include it in the solution


