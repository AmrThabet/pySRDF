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
		set_err("Process ID is invalid or access denied");
		return;
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

DWORD process::Allocate (DWORD preferedAddress,DWORD size)
{
	return handle->Allocate(preferedAddress,size);
};

//==================================================================
//Dbg

Dbg::Dbg(char* Filename,char* Commandline)
{
	Debugger = new cDbg(Filename,Commandline);
	if (Debugger->IsDebugging == false)
	{
		set_err("filename not found or access denied");
		return;
	}
	RefreshVariables();
	Process = new process(ProcessId);
	PE = new PEFile(Debugger->DebuggeePE);
	dis = new Disasm();
	LastError = -3;
}

Dbg::Dbg(process* proc)
{
	Debugger = new cDbg(proc->handle);
	
	RefreshVariables();
	Process = proc;
	PE = new PEFile(proc->Path);
	dis = new Disasm();
	LastError = -3;
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
	DebugStatus = Debugger->DebugStatus;
	ProcessId = Debugger->ProcessId;
	ThreadId = Debugger->ThreadId;
	ExceptionCode = Debugger->ExceptionCode;
	
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
	LastError = Debugger->Run();
	RefreshVariables();
	return LastError;
}

int Dbg::Step()
{
	UpdateRegisters();
	LastError = Debugger->Step();
	RefreshVariables();
	return LastError;
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

DISASM_INS* Dbg::disasm(DWORD vAddr)
{
	DWORD Addr = Process->handle->Read(vAddr,16);
	return dis->disasm((char*)Addr);
}

char* Dbg::GetLastError()
{
	switch(LastError)
	{
	case -3:
		return "The application didn't run";
	case DBG_STATUS_STEP:
		return "The application stepped one step";
	case DBG_STATUS_HARDWARE_BP:
		return "Hardware Breakpoint triggered";
	case DBG_STATUS_MEM_BREAKPOINT:
		return "Memory Breakpoint triggered";
	case DBG_STATUS_EXITPROCESS:
		return "The process exited normally";
	case DBG_STATUS_ERROR:
		return "Access voilation";
	case DBG_STATUS_INTERNAL_ERROR:
		return "Internal error";
	case DBG_STATUS_BREAKPOINT:
		return "Breakpoint reached";
	case ERROR_FILENAME:
		return "Wrong filename or access denied";
	}
	return "no error";
}

