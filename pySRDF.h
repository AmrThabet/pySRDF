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
using namespace Security::Libraries::Malware::Static;
using namespace Security::Libraries::Network::PacketGeneration;
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

/* Exception helpers */
extern int swig_c_error_num;
extern char swig_c_err_msg[256];
void set_err(const char *msg);
const char *err_occurred();

class PEFile;
void addattr(PEFile* obj,char* name, char* value);


#ifdef SWIG
%exception {
    const char *err;
    $action
    if (err = err_occurred()) {
        PyErr_SetString(PyExc_RuntimeError, err);
        return NULL;
    }
}


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

#endif

//===================================================================
//PE File:

#ifdef SWIG

#define DWORD int
#define BOOL bool

#define IMAGE_SCN_MEM_EXECUTE 0x20000000  // Section is executable.
#define IMAGE_SCN_MEM_READ    0x40000000  // Section is readable.
#define IMAGE_SCN_MEM_WRITE   0x80000000  // Section is writeable.

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

#define PAGE_READONLY          0x02     
#define PAGE_READWRITE         0x04     
#define PAGE_WRITECOPY         0x08     
#define PAGE_EXECUTE           0x10     
#define PAGE_EXECUTE_READ      0x20     
#define PAGE_EXECUTE_READWRITE 0x40     
#define PAGE_EXECUTE_WRITECOPY 0x80     
#define PAGE_GUARD            0x100     

#define MEM_IMAGE				0x1000000
#define MEM_PRIVATE				0x20000
#define MEM_MAPPED				0x40000

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
	DWORD Type;
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
	DWORD StartAddress;
};


%template (THREAD_INFOArray) array<THREAD_INFO*>;
%template (MEMORY_MAPArray) array<MEMORY_MAP*>;
%template (MODULEINFOArray) array<MODULEINFO*>;
%template (SEARCH_FOUNDArray) array<SEARCH_FOUND*>;
#endif

struct MODULEINFO
{
	DWORD Imagebase;
	DWORD64 Imagebase64;
	DWORD SizeOfImage;
	DWORD64 SizeOfImage64;
	char* Name;
	char* Path;
	char* MD5;
	DWORD nExportedAPIs;
};

struct SEARCH_FOUND
{
	DWORD Address;
	DWORD Allocationbase;
};

class process
{
public:
	//variables
	cProcess* handle;
	DWORD procHandle;
	__PEB  *ppeb;
	DWORD Imagebase;
	DWORD64 Imagebase64;
	DWORD SizeOfImage;
	DWORD64 SizeOfImage64;
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
	bool Is64bits;

	void RefreshThreads(){handle->RefreshThreads();};
	process(int processId);
	~process();
	void Read(DWORD startAddress,DWORD size,char **s, int *slen);
	DWORD Allocate (DWORD preferedAddress,DWORD size);
	void Write(DWORD startAddressToWrite ,char* buffer ,DWORD sizeToWrite){handle->Write(startAddressToWrite,(DWORD)buffer,sizeToWrite);};
	void DllInject(char* DLLFilename){handle->DllInject(DLLFilename);};
	void CreateThread(DWORD addressToFunction , DWORD addressToParameter){handle->CreateThread(addressToFunction,addressToParameter);};
	bool DumpProcess(char* Filename, DWORD Entrypoint, DWORD ImportUnloadingType){return handle->DumpProcess(Filename,Entrypoint,ImportUnloadingType);}; // Entrypoint == 0 means the same Entrypoint, ImportUnloadingType == PROC_DUMP_ZEROIMPORTTABLE or PROC_DUMP_UNLOADIMPORTTABLE
	array<SEARCH_FOUND*> Search(char* StringToSearch);
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
#define DBG_STATUS_DIDNT_STARTED	-3


#define DBG_CODE		0 
#define DBG_READWRITE	1
#define DBG_WRITE		3

#define DBG_BYTE			0
#define DBG_WORD			1
#define DBG_DWORD			3


#else
class Disasm;
struct DISASM_INS;

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
	int LastError;
	Disasm* dis;
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
	char* GetLastError();
	DISASM_INS* disasm(DWORD vAddr);
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

#endif
 struct MODRM{
        int length;
        int __items__[3];
        int __flags__[3];
		inline int items(int i) const throw(std::out_of_range)
		{
			if (i >= 3 || i < 0)
			  throw std::out_of_range("out of bounds access");
			return __items__[i];
		};
		inline int flags(int i) const throw(std::out_of_range)
		{
			if (i >= 3 || i < 0)
			  throw std::out_of_range("out of bounds access");
			return __flags__[i];
		};
    }; 
struct DISASM_INS
{
	char* ins;
    int length;
    char* cmd;
	int opcode;		//The opcode value
	int opcode2;
    int dest;
    int src;
    int other;      //used for mul to save the imm and used for any call to api to save the index of the api(it's num in APITable)
    MODRM modrm;
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
//------
//MEMORY FLAGS

#define MEM_READWRITE 0
#define MEM_READONLY 1
#define MEM_IMAGEBASE 2             //mixing readonly & readwrite so it needs to be check
#define MEM_DLLBASE 3
#define MEM_VIRTUALPROTECT 4
//--------
//EXCEPTIONS

#define EXP_EXCEED_MAX_ITERATIONS 0
#define EXP_INVALIDPOINTER 1
#define EXP_WRITEACCESS_DENIED 2
#define EXP_INVALID_OPCODE 3
#define EXP_DIVID_BY_ZERO 4
#define EXP_INVALID_INSTRUCTION 5
#define EXP_DIV_OVERFLOW 6
#define EXP_BREAKPOINT 7
#define ERROR_FILENAME 8
//-------
//Dump
#define DUMP_ZEROIMPORTTABLE    0
#define DUMP_FIXIMPORTTABLE     1
#define DUMP_UNLOADIMPORTTABLE  2

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

%template (DIRTYPAGES_STRUCTArray) array<DIRTYPAGES_STRUCT*>;
%template (MEMORY_STRUCTArray) array<MEMORY_STRUCT*>;
#endif
class Emulator
{
	CPokasEmu* emu;
	Disasm* dis;
	void RefreshRegisters();
	void UpdateRegisters();
	DWORD LastError;
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
	DWORD MaxIterations;				//Maximum Iterations to emulate (default = 1 million)
	//functions
	Emulator(char *FileName);
	Emulator(char *buff,int size);
	~Emulator();
	array<SEARCH_FOUND*> Search(char* StringToSearch);
	int Run();
	int Run(char* LogFile);
	int Step();
	int SetBp(char* Breakpoint);
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
	char* GetLastError();
	//DWORD DefineDLL(char* DLLName,char* DLLPath, DWORD VirtualAddress);	//The Desired Virtual Address
	//DWORD DefineAPI(DWORD DLLBase,char* APIName,int nArgs,DWORD APIFunc);
};

//=============================================================================================================
//Yara and SSDeep

#ifdef SWIG
%template (YARA_SEARCHArray) array<YARA_SEARCH*>;
#endif

struct YARA_SEARCH
{
	DWORD Offset;
	char* Name;
};

class YaraScanner
{
	cYaraScanner* YaraScan;
public:
	YaraScanner();
	~YaraScanner();
	void AddRule(char* Name, char* Rule);
	array<YARA_SEARCH*> Search(char* buff, DWORD size);
};


char* ssdeep(char* buff, DWORD size = 0);
DWORD ssdeepcompare(char* sig1, char* sig2);
char* md5(char* buff,DWORD size = 0);

//=============================================================================================================
//Packetyzer

#define PARAMTYPE_DWORD		1
#define PARAMTYPE_STRING	0
#define PARAMTYPE_MAC		2
#ifdef SWIG

//Session Types
#define CONN_NETWORK_UNKNOWN		0
#define CONN_NETWORK_ETHERNET		1
#define CONN_NETWORK_SSL			2

#define CONN_TRANSPORT_UNKNOWN		0
#define CONN_TRANSPORT_TCP			1
#define CONN_TRANSPORT_UDP			2
#define CONN_TRANSPORT_ICMP			3
#define CONN_TRANSPORT_IGMP			4

#define CONN_ADDRESSING_UNKOWN		0
#define CONN_ADDRESSING_ARP			1
#define CONN_ADDRESSING_IP			2

#define CONN_APPLICATION_UNKOWN		0
#define CONN_APPLICATION_DNS		1
#define CONN_APPLICATION_HTTP		2

//Packet Generator
#define GENERATE_TCP		1
#define GENERATE_UDP		2
#define GENERATE_ARP		3
#define GENERATE_ICMP		4

#define TCP_ACK				1
#define TCP_SYN				2
#define TCP_FIN				4
#define TCP_RST				8
#define TCP_PSH				16
#define TCP_URG				32
%template (SessionArray) array<Session*>;
%template (CONN_PARAMArray) array<CONN_PARAM*>;
%template (IP_INTArray) array<IP_INT*>;
%template (STRING_STRUCTArray) array<STRING_STRUCT*>;
%template (REQUESTSArray) array<REQUESTS*>;
%template (HASH_STRUCTArray) array<HASH_STRUCT*>;

#endif

struct IP_INT
{
	DWORD IP;
};

struct STRING_STRUCT
{
	char* Value;
};



//Application Layer Structures
struct DNS_STRUCT
{
	char* RequestedDomain;
	bool DomainIsFound;
	array<IP_INT*> ResolvedIPs;
};

struct HASH_STRUCT
{
	char* Key;
	char* Value;
};

struct REQUESTS
{
	char* RequestType;
	char* Address;
	array<HASH_STRUCT*> Arguments;
	DWORD ReplyNumber;
};

struct HTTP_STRUCT
{
	array<STRING_STRUCT*> Cookies;
	char* UserAgent;
	char* Referer;
	char* ServerType;
	array<REQUESTS*> Request;
	DWORD nFiles;
	cFile** Files;
	void DumpFile(DWORD index, char* Filename)
	{
		if (index >= nFiles)
		{
			set_err("index out of range");
			return;
		}
		FILE* f = fopen(Filename,"w");
		if(f == NULL)
		{
			set_err("Wrong Filename or access denied");
			return;
		};

		fwrite((const void*) Files[index]->BaseAddress,1,Files[index]->FileLength,f);
		fclose(f);
	};
};

//For parameters 
struct CONN_PARAM
{
	char* Name;
	char* sValue;
	DWORD nValue;
	char  MAC[6];
	DWORD Type;
};
class Session
{
	cConnection* conn;
public:
	DNS_STRUCT* DNS;
	HTTP_STRUCT* HTTP;
	array<CONN_PARAM*> __params__;
	Session(cConnection* connection);
	~Session();
	void ReadPacket(DWORD index,char **s, int *slen);
#ifdef SWIG
%pythoncode %{
def __getattr__(self,Name):
    for param in self.__params__:
        if param.Name == Name and param.Type == PARAMTYPE_DWORD:
            return param.nValue
        elif param.Name == Name and param.Type == PARAMTYPE_STRING:
            return param.sValue
        elif param.Name == Name and param.Type == PARAMTYPE_MAC:
            return param.MAC
	if Name == "DNS" and self.ApplicationType == CONN_APPLICATION_DNS:
			return getattr(self,Name)
    elif Name == "HTTP" and self.ApplicationType == CONN_APPLICATION_HTTP:
			return getattr(self,Name)

    raise AttributeError
%}
#endif
};

class Traffic
{
	cTraffic* traffic;
public:
	array<Session*> Sessions;
	Traffic(cTraffic* t);
	~Traffic(){};
};

class PcapFile
{
	cPcapFile* Pcap;
public:
	DWORD nPackets;
	Traffic* traffic;
	PcapFile(char* Filename);
	~PcapFile();

};

char* IPToString(DWORD IP);
char* MACToString(char MAC[6]);

class PacketGenerator
{
	cPacketGen* pGen;
public:
	PacketGenerator(DWORD type);
	bool SetMACAddress(char* src_mac, char* dest_mac);
	bool SetIPAddress(char* src_ip, char* dest_ip);
	bool SetPorts(short src_port, short dest_port);

	bool CustomizeTCP(char* tcp_data, DWORD tcp_data_size, short tcp_flags);
	bool CustomizeUDP(char* udp_data, DWORD udp_data_size);
	bool CustomizeICMP(char icmp_type, char icmp_code, char* icmp_data, DWORD icmp_data_size);

	void DumpPacket(char **s, int *slen);
};
//*/