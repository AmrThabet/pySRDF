// emulator.cpp : For the disassembler and the emulator
//

#include "stdafx.h"
#include "pySRDF.h"
#include <Shlobj.h>

using namespace std;
Disasm::Disasm()
{
	dis = new CPokasAsm();
	memset(&temp_ins,0,sizeof(DISASM_INSTRUCTION));
}

DISASM_INS* Disasm::disasm (char bytes[])
{
	DISASM_INS* ins = (DISASM_INS*)malloc(sizeof(DISASM_INS));
	memset(ins,0,sizeof(DISASM_INS));
	memset(&temp_ins,0,sizeof(DISASM_INSTRUCTION));
	dis->Disassemble(bytes,&temp_ins);
	DWORD len;
	ins->ins = dis->Disassemble(bytes,len);
	ins->cmd = (char*)temp_ins.opcode->c_str();
	ins->opcode = temp_ins.hde.opcode;
	ins->opcode2 = temp_ins.hde.opcode2;
	ins->length = temp_ins.hde.len;
	ins->dest = temp_ins.ndest;
	ins->src = temp_ins.nsrc;
	ins->category = temp_ins.category;
	ins->flags = temp_ins.flags;
	ins->other = temp_ins.other;
	ins->modrm.length = temp_ins.modrm.length;
	for (int i = 0;i < 3;i++)
	{
		ins->modrm.__items__[i] = temp_ins.modrm.items[i];
		ins->modrm.__flags__[i] = temp_ins.modrm.flags[i];
	}
	return ins;
}

void Disasm::assemble(char* ins, char **s, int *slen)
{
	DWORD len;
	char* ins_bytes = dis->Assemble(ins,len);
	*s = ins_bytes;
	*slen = len;
}

Disasm::~Disasm()
{
	delete dis;
}

//---------------------------------------------------------------------------------------

Emulator::Emulator(char *FileName)
{
	char* DLLPath = (char*)malloc(MAX_PATH);
	memset(DLLPath,0,MAX_PATH);
	//throw(std::out_of_range("wrong filename"));
	DWORD Length = SHGetSpecialFolderPath(0, DLLPath, CSIDL_SYSTEMX86, false);
	cString SysPath = DLLPath;
	SysPath += "\\";
	LastError = -1;
	try
	{
		emu = new CPokasEmu(FileName,SysPath.GetChar());
	}
	catch (int x)
	{

		LastError = 8;
		set_err(GetLastError());
		GetLastError();
		return;
	}
	dis = new Disasm();
	Imagebase = emu->GetImagebase();
	RefreshRegisters();
}

Emulator::Emulator(char *buff,int size)
{
	char* DLLPath = (char*)malloc(MAX_PATH);
	memset(DLLPath,0,MAX_PATH);
	DWORD Length = GetSystemDirectoryA(DLLPath,MAX_PATH);
	emu = new CPokasEmu(buff,size,PROCESS_SHELLCODE, DLLPath);
	dis = new Disasm();
	Imagebase = emu->GetImagebase();
	RefreshRegisters();
	LastError = -1;
}

int Emulator::Run()
{
	UpdateRegisters();
	LastError = emu->Emulate();
	RefreshRegisters();
	return LastError;
}

int Emulator::Run(char* LogFile)
{
	UpdateRegisters();
	int LastError = emu->Emulate(LogFile);
	RefreshRegisters();
	return LastError;
}

int Emulator::Step()
{
	UpdateRegisters();
	LastError = emu->Step();
	RefreshRegisters();
	return LastError;
}

int Emulator::SetBp(char* Breakpoint)
{
	try
	{
		return emu->SetBreakpoint(Breakpoint);
	}
	catch(int x)
	{
		cout << emu->process->debugger->GetLastError().c_str() << "\n";
		return -1;
	}
}

void Emulator::RemoveBp(int index)
{
	return emu->DisableBreakpoint(index);
}

DWORD Emulator::GetRealAddr(DWORD vAddr)
{
	return emu->GetRealAddr(vAddr);
}

void Emulator::ClearDirtyPages()
{
	return emu->ClearDirtyPages();
}

int Emulator::Dump(char* OutputFile, int ImportFixType)
{
	return emu->MakeDumpFile(OutputFile,ImportFixType);
}

DWORD Emulator::GetReg(int index)
{
	return emu->GetReg(index);
}

void Emulator::SetReg(int index,DWORD value)
{
	emu->SetReg(index,value);
	RefreshRegisters();
}

DISASM_INS* Emulator::disasm(DWORD vAddr)
{
	DWORD Addr = emu->GetRealAddr((DWORD)vAddr);
	return dis->disasm((char*)Addr);
}

void Emulator::Read(DWORD vAddr,DWORD size,char **s, int *slen)
{
	char* Addr = (char*)emu->GetRealAddr((DWORD)vAddr);
	if (Addr)
	{
		*s = (char*)malloc(size);
		memcpy(*s,Addr,size);
		*slen = size;
	}
}

void Emulator::Write(DWORD vAddr, char* buff, DWORD size)
{
	char* Addr = (char*)emu->GetRealAddr((DWORD)vAddr);
	if (Addr)
	{
		memcpy(Addr,buff,size);
	}
}

array<DIRTYPAGES_STRUCT*> Emulator::GetDirtyPages()
{
	array<DIRTYPAGES_STRUCT*> Pages;
	Pages.init(sizeof(DIRTYPAGES_STRUCT));
	for (int i = 0;i < emu->GetNumberOfDirtyPages();i++)
	{
		Pages.additem(emu->GetDirtyPage(i));
	}
	return Pages;
}

array<MEMORY_STRUCT*> Emulator::GetMemoryPage()
{
	array<MEMORY_STRUCT*> Pages;
	Pages.init(sizeof(MEMORY_STRUCT));
	for (int i = 0;i < emu->GetNumberOfMemoryPages();i++)
	{
		Pages.additem(emu->GetMemoryPage(i));
	}
	return Pages;
}

MEMORY_STRUCT* Emulator::GetMemoryPageByVA(DWORD vAddr)
{
	return emu->GetMemoryPageByVA(vAddr);
}

Emulator::~Emulator()
{
	if (LastError != 8)
	{
		delete emu;
		delete dis;
	}
}

void Emulator::RefreshRegisters()
{
	eax = emu->GetReg(0);
	ecx = emu->GetReg(1);
	edx = emu->GetReg(2);
	ebx = emu->GetReg(3);
	esp = emu->GetReg(4);
	ebp = emu->GetReg(5);
	esi = emu->GetReg(6);
	edi = emu->GetReg(7);
	eip = emu->GetEip();
	EFlags = emu->GetEFLAGS();
	
}

void Emulator::UpdateRegisters()
{
	emu->SetReg(0,eax);
	emu->SetReg(1,ecx);
	emu->SetReg(0,edx);
	emu->SetReg(0,ebx);
	emu->SetReg(0,esp);
	emu->SetReg(0,ebp);
	emu->SetReg(0,esi);
	emu->SetReg(0,edi);
	emu->SetEip(eip);
	emu->SetEFLAGS(EFlags);
}

char* Emulator::GetLastError()
{
	switch(LastError)
	{
	case -1:
		return "The application didn't run";
	case EXP_EXCEED_MAX_ITERATIONS:
		return "The application exceed the maximum iterations. Run again";
	case EXP_INVALIDPOINTER:
		return "Invalid pointer";
	case EXP_WRITEACCESS_DENIED:
		return "Unable to write, access denied";
	case EXP_INVALID_OPCODE:
		return "Invalid instruction";
	case EXP_DIVID_BY_ZERO:
		return "Divid by Zero";
	case EXP_INVALID_INSTRUCTION:
		return "Invalid instruction";
	case EXP_DIV_OVERFLOW:
		return "Divid Overflow";
	case EXP_BREAKPOINT:
		return "Breakpoint reached";
	case ERROR_FILENAME:
		return "Wrong filename or access denied";
	}
	return "no error";
}