#ifdef SWIG
%module pySRDF
%{
#include "stdafx.h"
#include "pySRDF.h"
#include <exception>
%}

%include "cstring.i"
%include "std_except.i"
#else
/* Don’t wrap these declarations. */
#include "../winSRDF/User-Mode/SRDF.h"
using namespace Security::Elements::String;
using namespace Security::Targets::Files;
using namespace Security::Targets::Memory;
using namespace Security::Libraries::Malware::Dynamic;
#endif

template <typename Type, size_t N>
struct wrapped_array {
	size_t Size;
	Type data[N];
  void setlength(size_t i)
  {
	  Size = i;
  };
};

template <typename Type>
struct array {
	cList* data;
	array(cList* y)
	{
		data = y;
	}
	array(){};
	void init(size_t size)
	{
		data = new cList(size);
	}
	void setvalues(cList* values)
	{
		  data = values;
	}
	void additem(Type Item)
	{
		data->AddItem((char*)Item);
	}
	void clear()
	{
		delete data;
	}
};
#ifdef SWIG



%extend wrapped_array {
  inline size_t __len__() const { return self->Size; }

  inline const Type& __getitem__(size_t i) const throw(std::out_of_range) {
    if (i >= self->Size || i < 0)
      throw std::out_of_range("out of bounds access");
    return self->data[i];
  }

  inline void __setitem__(size_t i, const Type& v) throw(std::out_of_range) {
    if (i >= self->Size || i < 0)
      throw std::out_of_range("out of bounds access");
    self->data[i] = v;
  }

}

%extend array{
  inline size_t __len__() const { return self->data->GetNumberOfItems(); }

  inline const Type& __getitem__(size_t i) const throw(std::out_of_range) {
    if (self->data->GetItem(i) == NULL)
		throw std::out_of_range("out of bounds access");
	return (Type)self->data->GetItem(i);
  }
}
%cstring_output_allocate_size(char **s, int *slen, free(*$1));

%template (TEST_STRUCTArray) array<TEST_STRUCT*>;


#endif

/* C declarations */
char* print_to_python();

struct TEST_STRUCT
{
	int x;
	int y;
	int z;
};


struct TestArray
{
	wrapped_array<TEST_STRUCT*,1> arr;
};

class Test
{
public:
	char* x;
	Test(char* str);
	~Test();
	array<TEST_STRUCT*> arr;
	int AddString(char* str);
	void GetValues();
};
//===================================================================
//PE File:

#ifdef SWIG

#define DWORD int
#define BOOL bool


class cFile;
class cPEFile : public cFile
{
	cPEFile(char* filename){};
};

struct SECTION_STRUCT
{
	char* SectionName;
	DWORD VirtualAddress;
	DWORD VirtualSize;
	DWORD PointerToRawData;
	DWORD SizeOfRawData;
	DWORD Characterisics;
	DWORD RealAddr;
};
struct IMPORTTABLE_API
{
	char* APIName;
	DWORD APIAddressPlace;
};

struct EXPORTFUNCTION {
	char* funcName;
	WORD funcOrdinal;
	DWORD funcRVA;
};

%template (EXPORTFUNCTIONArray) array<EXPORTFUNCTION*> ;
%template (IMPORTTABLEArray) array<IMPORTTABLE_API*>;
%template (SECTION_STRUCTArray) array<SECTION_STRUCT*>;
%template (IMPORT_DLLArray) array<IMPORT_DLL*>;

#endif

struct IMPORT_DLL
{
	char* DLLName;
	array<IMPORTTABLE_API*> APIs;
};

struct EXPORT_TABLE 
{
	DWORD nFunctions;
	DWORD nNames;
	DWORD Base;
	PDWORD pFunctions;
	PDWORD pNames;
	PWORD pNamesOrdinals;
	array<EXPORTFUNCTION*> Functions;
};


class PEFile
{
	void AnalyzeFile();
public:
	//variables:
	int Magic;
	DWORD Subsystem;
	DWORD Imagebase;
	DWORD SizeOfImage;
	DWORD Entrypoint;
	DWORD FileAlignment;
	DWORD SectionAlignment;
	cPEFile* handle;
	array<SECTION_STRUCT*> Sections;
	array<IMPORT_DLL*> ImportTable;
	EXPORT_TABLE ExportTable;
	bool IsFound;

	//functions:
	void Read(DWORD Offset, DWORD Size,char** s, int* slen);
	PEFile(char* filename);
	PEFile(cPEFile* PE);
	~PEFile();
	static bool identify(cFile* File);
	DWORD RVAToOffset(DWORD RVA);
	DWORD OffsetToRVA(DWORD RawOffset);
};

//=========================================================================
//Process class:

#ifdef SWIG

typedef struct FLOATING_SAVE_AREA {
    DWORD   ControlWord;
    DWORD   StatusWord;
    DWORD   TagWord;
    DWORD   ErrorOffset;
    DWORD   ErrorSelector;
    DWORD   DataOffset;
    DWORD   DataSelector;
    BYTE    RegisterArea[80];
    DWORD   Cr0NpxState;
};

typedef struct CONTEXT {
    DWORD ContextFlags;
    DWORD   Dr0;
    DWORD   Dr1;
    DWORD   Dr2;
    DWORD   Dr3;
    DWORD   Dr6;
    DWORD   Dr7;
    FLOATING_SAVE_AREA FloatSave;
    DWORD   SegGs;
    DWORD   SegFs;
    DWORD   SegEs;
    DWORD   SegDs;
    DWORD   Edi;
    DWORD   Esi;
    DWORD   Ebx;
    DWORD   Edx;
    DWORD   Ecx;
    DWORD   Eax;

    DWORD   Ebp;
    DWORD   Eip;
    DWORD   SegCs;              // MUST BE SANITIZED
    DWORD   EFlags;             // MUST BE SANITIZED
    DWORD   Esp;
    DWORD   SegSs;
    BYTE    ExtendedRegisters[512];

};

struct MEMORY_MAP
{
	DWORD Address;
	DWORD Size;
	DWORD Protection;
	DWORD AllocationBase;
};

struct THREAD_INFO
{
	DWORD ThreadId;
	HANDLE Handle;
	CONTEXT Context;
	DWORD TEB;
	DWORD StackBase;
	DWORD StackLimit;
	DWORD SEH;
};

%template (THREAD_INFOArray) array<THREAD_INFO*>;
%template (MEMORY_MAPArray) array<MEMORY_MAP*>;
%template (MODULEINFOArray) array<MODULEINFO*>;
#endif

struct MODULEINFO
{
	DWORD Imagebase;
	DWORD SizeOfImage;
	char* Name;
	char* Path;
	char* MD5;
	DWORD nExportedAPIs;
};

class process
{
public:
	//variables
	cProcess* handle;
	DWORD procHandle;
	__PEB  *ppeb;
	DWORD Imagebase;
	DWORD SizeOfImage;
	char* Name;
	char* Path;
	char* MD5;
	DWORD Pid;
	DWORD PPid;
	char* Commandline;
	array<MODULEINFO*> ModuleList;
	array<MEMORY_MAP*> MemoryMap;
	array<THREAD_INFO*> Threads;
	bool IsFound;

	void RefreshThreads(){handle->RefreshThreads();};
	process(int processId);
	~process();
	void Read(DWORD startAddress,DWORD size,char **s, int *slen);
	char* Allocate (DWORD preferedAddress,DWORD size){return (char*)handle->Allocate(preferedAddress,size);};
	void Write(DWORD startAddressToWrite ,DWORD buffer ,DWORD sizeToWrite){handle->Write(startAddressToWrite,buffer,sizeToWrite);};
	void DllInject(char* DLLFilename){handle->DllInject(DLLFilename);};
	void CreateThread(DWORD addressToFunction , DWORD addressToParameter){handle->CreateThread(addressToFunction,addressToParameter);};
	bool DumpProcess(char* Filename, DWORD Entrypoint, DWORD ImportUnloadingType){return handle->DumpProcess(Filename,Entrypoint,ImportUnloadingType);}; // Entrypoint == 0 means the same Entrypoint, ImportUnloadingType == PROC_DUMP_ZEROIMPORTTABLE or PROC_DUMP_UNLOADIMPORTTABLE
};


//=========================================================================
//Debugger

#ifdef SWIG
#define DBG_STATUS_STEP				4
#define DBG_STATUS_HARDWARE_BP		3
#define DBG_STATUS_MEM_BREAKPOINT	2
#define DBG_STATUS_BREAKPOINT		1
#define DBG_STATUS_EXITPROCESS		0
#define DBG_STATUS_ERROR			-1
#define DBG_STATUS_INTERNAL_ERROR	-2

#else
class cDbg : public cDebugger
{
public:
	cDbg(cString Filename, cString Commandline = cString(" ")) : cDebugger(Filename,Commandline){};
	cDbg(Security::Targets::Memory::cProcess* Process): cDebugger(Process){};
	~cDbg(){};
	virtual void DLLLoadedNotifyRoutine(){};
	virtual void DLLUnloadedNotifyRoutine(){};
	virtual void ThreadCreatedNotifyRoutine(){};
	virtual void ThreadExitNotifyRoutine(){};
	virtual void ProcessExitNotifyRoutine(){};
};

#endif

class Dbg
{
	void RefreshVariables();
	void UpdateRegisters();
	cDbg* Debugger;
public:
	//variables
	BOOL IsDebugging;
	process* Process;
	PEFile* PE;
	DWORD eax;
	DWORD ecx;
	DWORD edx;
	DWORD ebx;
	DWORD esp;
	DWORD ebp;
	DWORD esi;
	DWORD edi;
	DWORD eip;
	DWORD EFlags;
	DWORD DebugStatus;
	DWORD ProcessId;
	DWORD ThreadId;
	DWORD ExceptionCode;
	DWORD GetReg(DWORD index);
	void SetReg(DWORD index, DWORD newValue);
	//functions
	Dbg(char* Filename,char* Commandline = " ");
	Dbg(process* proc);
	int Run();
	int Step();
	void Exit();

	BOOL SetBp(DWORD Address);
	void RemoveBp(DWORD Address);
	BOOL SetHardBp(DWORD Address,DWORD Type, int Size);
	void RemoveHardBp(DWORD Address);
	BOOL SetMemoryBp(DWORD Address,DWORD Size, DWORD Type);
	void RemoveMemoryBp(DWORD Address);
};

//======================================================================================================
//Disassembler

#ifdef SWIG

//Assembler states
#define NO_SRCDEST  0x80000000         // no opcodes     

#define DEST_REG    0x00000100
#define DEST_RM     0x00000200
#define DEST_IMM    0x00000400        //IMM8 or IMM32 
#define DEST_BITS32 0x00000800
#define DEST_BITS16 0x00001000
#define DEST_BITS8  0x00002000

#define SRC_REG     0x00004000
#define SRC_NOSRC   0x00008000
#define SRC_RM      0x00010000
#define SRC_IMM     0x00020000        //IMM8 or IMM32 
#define SRC_BITS32  0x00040000
#define SRC_BITS16  0x00001000        //the same as  DEST_BITS16
#define SRC_BITS8   0x00080000

#define RM_SIB      0x00100000       // it will not differ dest or src because it should be one rm
#define INS_UNDEFINED 0x00200000    //for the disasembler only
#define INS_INVALID 0x00400000       //invalid instruction (returned by hde32) 
#define MOVXZ_SRC16 0x00800000
#define MOVXZ_SRC8  0x01000000
#define EIP_UPDATED 0x02000000
#define API_CALL    0x04000000

//ModRM states
#define RM_REG      0x00000001
#define RM_DISP8    0x00000002
#define RM_DISP16   0x00000004
#define RM_DISP32   0x00000008
#define RM_DISP     0x00000010
#define RM_MUL2     0x00000020
#define RM_MUL4     0x00000040
#define RM_MUL8     0x00000080
#define RM_ADDR16   0x00000100

//FPU States

#define FPU_NULL        0x00000100       //no source or destinaion
#define FPU_DEST_ONLY   0x00000200       // Destination only 
#define FPU_SRCDEST     0x00000400        // with source and destination
#define FPU_DEST_ST     0x00000800        // destination == ST0
#define FPU_SRC_STi     0x00000800        // source == STi (the same as before)
#define FPU_DEST_STi    0x00001000        // destination == STi
#define FPU_SRC_ST      0x00001000        // source == ST0 (the same as before)
#define FPU_DEST_RM     0x00002000        // destination is RM
#define FPU_MODRM       0x00002000        // destination is RM & there's a ModRM
#define FPU_BITS32      0x00004000        
#define FPU_BITS16      0x00008000        
#define FPU_BITS64      0x00010000
#define FPU_BITS80      0x00020000		  //tbyte []


//MMX States

#define MMX_NULL		0x00000100			//no source or destinaion


//Opcode Categories

#define OP_TYPE_I386	0x00000001
#define OP_TYPE_FPU		0x00000002
#define OP_TYPE_MMX		0x00000004
#define OP_TYPE_SSE		0x00000008

#define OP_TYPE_ARTHIMETIC1			0x00000010				//add,sub,xor,or,shl,shr,and,ror,rol and the same for fpu,mmx
#define OP_TYPE_ARTHIMETIC2			0x00000020				//mul,div ...
#define OP_TYPE_ARTHIMETIC3			0x00000040				//all abnormal fpu mathimatics
#define OP_TYPE_FLOW_REDIRECTION	0x00000080				//like call,jmp,jcc, ...
#define OP_TYPE_FLAG_TEST			0x000000C0				//cmp,test, or ... 
#define OP_TYPE_PRIVILEDGE			0x00000100				//like in,out ...
#define OP_TYPE_DATA_MANIPULATE		0x00000200				//movs, lods,stos,xchg, lea ... (not included xadd)
#define OP_TYPE_FLAG_MANIPULATE		0x00000400				//like cli,sti ...
#define OP_TYPE_NOP					0x00000800				//nop instructions
#define OP_TYPE_ARTIMITIC1_FLAGS	0x00000C10				//it's a part of Arthimitic 1 and it's like adc ...
#define OP_TYPE_UNKNOWN_BEHAVIOR	0x00001000				//like jp, aad,daa ... 
#define OP_TYPE_STACK_MANIPULATE	0x00002000				//like push, pop ..

%template (intArray) array<int>;



#endif

struct DISASM_INS
{
	char* tostr;
    int length;
    char* cmd;
	int opcode;		//The opcode value
	int opcode2;
    int dest;
    int src;
    int other;      //used for mul to save the imm and used for any call to api to save the index of the api(it's num in APITable)
    struct {
            int length;
            int items[3];
            int flags[3];
    } modrm;
    int flags;
	DWORD category;
};

class Disasm
{
	DISASM_INSTRUCTION temp_ins;
	CPokasAsm* dis;
public:
	DWORD length;

	Disasm();
	~Disasm();
	DISASM_INS* disasm (char bytes[]);
	void assemble(char* ins, char **s, int *slen);
};

//========================================================================================
//Emulator
#ifdef SWIG
struct MEMORY_STRUCT
{
       DWORD VirtualAddr;
       DWORD RealAddr;
       DWORD Size;
       DWORD Flags;
};

struct DIRTYPAGES_STRUCT         //the changes in the memory during the emulation
{                               
       DWORD vAddr;             //here the pointer to the virtual memory not the real pointer
       DWORD Size;
       DWORD Flags;
}; 

#endif
class Emulator
{
	CPokasEmu* emu;
	Disasm* dis;
	void RefreshRegisters();
	void UpdateRegisters();
public:
	//variables:
	DWORD eax;
	DWORD ecx;
	DWORD edx;
	DWORD ebx;
	DWORD esp;
	DWORD ebp;
	DWORD esi;
	DWORD edi;
	DWORD eip;
	DWORD EFlags;
	DWORD LastInsLength;
	DWORD Imagebase;


	//functions
	Emulator(char *FileName);
	Emulator(char *buff,int size);
	~Emulator();
	int Run();
	int Run(char* LogFile);
	int Step();
	int SetBp(char* Breakpoint);
	//int SetBreakpoint(char* FuncName,DWORD BreakpointFunc);
	void RemoveBp(int index);
	array<DIRTYPAGES_STRUCT*> GetDirtyPages();
	array<MEMORY_STRUCT*> GetMemoryPage();
	MEMORY_STRUCT* GetMemoryPageByVA(DWORD vAddr);
	DWORD GetRealAddr(DWORD vAddr);
	void ClearDirtyPages();
	int Dump(char* OutputFile, int ImportFixType);
	DWORD GetReg(int index);
	void SetReg(int index,DWORD value);
	DISASM_INS* disasm(DWORD vAddr);
	void Read(DWORD vAddr,DWORD size,char **s, int *slen);
	void Write(DWORD vAddr, char* buff, DWORD size);
	//DWORD DefineDLL(char* DLLName,char* DLLPath, DWORD VirtualAddress);	//The Desired Virtual Address
	//DWORD DefineAPI(DWORD DLLBase,char* APIName,int nArgs,DWORD APIFunc);
};


/*
// SWIG interface to our PlotWidget 

// Grab a Python function object as a Python object.
%typemap(python,in) PyObject *pyfunc {
  if (!PyCallable_Check($source)) {
      PyErr_SetString(PyExc_TypeError, "Need a callable object!");
      return NULL;
  }
  $target = $source;
}

// Type mapping for grabbing a FILE * from Python
%typemap(python,in) FILE * {
  if (!PyFile_Check($source)) {
      PyErr_SetString(PyExc_TypeError, "Need a file!");
      return NULL;
  }
  $target = PyFile_AsFile($source);
}

// Grab the class definition

%{
// This function matches the prototype of the normal C callback
//   function for our widget. However, we use the clientdata pointer
 //  for holding a reference to a Python callable object.

static double PythonCallBack(double a, void *clientdata)
{
   PyObject *func, *arglist;
   PyObject *result;
   double    dres = 0;
   
   func = (PyObject *) clientdata;               // Get Python function
   arglist = Py_BuildValue("(d)",a);             // Build argument list
   result = PyEval_CallObject(func,arglist);     // Call Python
   Py_DECREF(arglist);                           // Trash arglist
   if (result) {                                 // If no errors, return double
     dres = PyFloat_AsDouble(result);
   }
   Py_XDECREF(result);
   return dres;
}
%}

// Attach a new method to our plot widget for adding Python functions
%addmethods PlotWidget {
   // Set a Python function object as a callback function
   // Note : PyObject *pyfunc is remapped with a typempap
   void set_pymethod(PyObject *pyfunc) {
     self->set_method(PythonCallBack, (void *) pyfunc);
     Py_INCREF(pyfunc);
   }
}
*/