// memory.cpp : For all cProcess and the debugger
//

#include "stdafx.h"
#include "pySRDF.h"

process::process(int processId)
{
	handle = new cProcess(processId);
	IsFound = handle->IsFound();
	if (IsFound)
	{
		procHandle = handle->procHandle;
		ppeb = handle->ppeb;
		Imagebase = handle->ImageBase;
		cout << handle->ImageBase << "\n";
		SizeOfImage = handle->SizeOfImage;
		Name = handle->processName.GetChar();
		Path = handle->processPath.GetChar();
		MD5 = handle->processMD5.GetChar();
		Pid = handle->ProcessId;
		PPid = handle->ParentID;
		Commandline = handle->CommandLine.GetChar();
		
		MemoryMap.setvalues(&handle->MemoryMap);
		Threads.setvalues(handle->Threads);

		ModuleList.init(sizeof(MODULEINFO));
		for (int i = 0; i < handle->modulesList.GetNumberOfItems(); i++)
		{
			MODULEINFO x = {0};
			MODULE_INFO* Item = (MODULE_INFO*)handle->modulesList.GetItem(i);
			x.Imagebase = Item->moduleImageBase;
			x.SizeOfImage = Item->moduleSizeOfImage;
			x.Name = Item->moduleName->GetChar();
			x.MD5 = Item->moduleMD5->GetChar();
			x.Path = Item->modulePath->GetChar();
			x.nExportedAPIs = Item->nExportedAPIs;
			ModuleList.additem(&x);
		}
	}
	else
	{
		procHandle = 0;
		ppeb = 0;
		Imagebase = 0;
		SizeOfImage = 0;
		Name = "";
		Path = "";
		MD5 = "";
		Pid = 0;
		PPid = 0;
		Commandline = "";
		ModuleList.init(sizeof(MODULE_INFO));
		MemoryMap.init(sizeof(MEMORY_MAP));
		Threads.init(sizeof(THREAD_INFO));
	}
}

process::~process()
{
	delete handle;
}

void process::Read(DWORD startAddress,DWORD size,char **s, int *slen)
{
	*s = (char*)handle->Read(startAddress,size);
	*slen = size;
};

//==================================================================
//Dbg

Dbg::Dbg(char* Filename,char* Commandline)
{
	Debugger = new cDbg(Filename,Commandline);
	RefreshVariables();
	Process = new process(ProcessId);
	PE = new PEFile(Debugger->DebuggeePE);
}

Dbg::Dbg(process* proc)
{
	Debugger = new cDbg(proc->handle);
	
	RefreshVariables();
	Process = proc;
	PE = new PEFile(proc->Path);
}

void Dbg::UpdateRegisters()
{
	Debugger->Reg[0] = eax;
	Debugger->Reg[1] = ecx;
	Debugger->Reg[2] = edx;
	Debugger->Reg[3] = ebx;
	Debugger->Reg[4] = esp;
	Debugger->Reg[5] = ebp;
	Debugger->Reg[6] = esi;
	Debugger->Reg[7] = edi;
	Debugger->EFlags = EFlags;
	Debugger->Eip = eip;
	Debugger->UpdateRegisters();
}


void Dbg::RefreshVariables()
{
	IsDebugging = Debugger->IsDebugging;
	eax = Debugger->Reg[0];
	ecx = Debugger->Reg[1];
	edx = Debugger->Reg[2];
	ebx = Debugger->Reg[3];
	esp = Debugger->Reg[4];
	ebp = Debugger->Reg[5];
	esi = Debugger->Reg[6];
	edi = Debugger->Reg[7];
	EFlags = Debugger->EFlags;
	eip = Debugger->Eip;
	DebugStatus = DebugStatus;
	ProcessId = ProcessId;
	ThreadId = ThreadId;
	ExceptionCode = ExceptionCode;
	
}

DWORD Dbg::GetReg(DWORD index)
{
	if (index < 8)
		return Debugger->Reg[index];
	else
		return 0;
}

void Dbg::SetReg(DWORD index, DWORD newValue)
{
	if (index < 8)
		Debugger->Reg[index] = newValue;
	RefreshVariables();
}


int Dbg::Run()
{
	UpdateRegisters();
	int res = Debugger->Run();
	RefreshVariables();
	return res;
}

int Dbg::Step()
{
	UpdateRegisters();
	int res = Debugger->Step();
	RefreshVariables();
	return res;
}

void Dbg::Exit()
{
	UpdateRegisters();
	Debugger->Exit();
	RefreshVariables();
}

BOOL Dbg::SetBp(DWORD Address)
{
	return Debugger->SetBreakpoint(Address);
}

void Dbg::RemoveBp(DWORD Address)
{
	Debugger->RemoveBreakpoint(Address);
}

BOOL Dbg::SetHardBp(DWORD Address,DWORD Type, int Size)
{
	return Debugger->SetHardwareBreakpoint(Address,Type, Size);
}

void Dbg::RemoveHardBp(DWORD Address)
{
	Debugger->RemoveHardwareBreakpoint(Address);
}

BOOL Dbg::SetMemoryBp(DWORD Address,DWORD Size, DWORD Type)
{
	return Debugger->SetMemoryBreakpoint(Address,Size,Type);
}

void Dbg::RemoveMemoryBp(DWORD Address)
{
	Debugger->RemoveMemoryBreakpoint(Address);
}
