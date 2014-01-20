// files.cpp : For all cFile and inherited classes
//

#include "stdafx.h"
#include "pySRDF.h"


PEFile::PEFile(char* filename)
{
	handle = new cPEFile(filename);
	AnalyzeFile();
}

PEFile::PEFile(cPEFile* PE)
{
	handle = PE;
	AnalyzeFile();
}

void PEFile::AnalyzeFile()
{
	IsFound = handle->IsFound();
	if (IsFound)
	{
		Magic = handle->Magic;
		Subsystem = handle->Subsystem;
		Imagebase = handle->Imagebase;
		SizeOfImage = handle->SizeOfImage;
		Entrypoint = handle->Entrypoint;
		FileAlignment = handle->FileAlignment;
		SectionAlignment = handle->SectionAlignment;

		//Set Sections
		Sections.init(sizeof(SECTION_STRUCT));
		for (int i = 0;i < handle->nSections; i++)
		{
			Sections.additem(&handle->Section[i]);
		}

		//Set ImportTable
		ImportTable.init(sizeof(IMPORT_DLL));
		for (int i = 0;i < handle->ImportTable.nDLLs; i++)
		{
			IMPORT_DLL DLL  = {0};
			DLL.DLLName = handle->ImportTable.DLL[i].DLLName;

			DLL.APIs.init(sizeof(IMPORTTABLE_API));
			for (int l = 0;l < handle->ImportTable.DLL[i].nAPIs; l++)
			{
				DLL.APIs.additem(&handle->ImportTable.DLL[i].API[l]);
			}
			ImportTable.additem(&DLL);
		}

		//Set ExportTable
		ExportTable.Base = handle->ExportTable.Base;
		ExportTable.nFunctions = handle->ExportTable.nFunctions;
		ExportTable.nNames = handle->ExportTable.nNames;
		ExportTable.pFunctions = handle->ExportTable.pFunctions;
		ExportTable.pNames = handle->ExportTable.pNames;
		ExportTable.pNamesOrdinals = handle->ExportTable.pNamesOrdinals;

		ExportTable.Functions.init(sizeof(EXPORTFUNCTION));
		ExportTable.nNames = 0;
		for (int i = 0;i < ExportTable.nNames; i++)
			ExportTable.Functions.additem(&handle->ExportTable.Functions[i]);
	}
	else
	{
		set_err("filename not found or access denied");
		return;
	}
}
PEFile::~PEFile()
{
	delete handle;
}

DWORD PEFile::RVAToOffset(DWORD RVA)
{
	return handle->RVAToOffset(RVA);
}

DWORD PEFile::OffsetToRVA(DWORD RawOffset)
{
	return handle->OffsetToRVA(RawOffset);
}

bool PEFile::identify(cFile* File)
{
	return cPEFile::identify(File);
}

void PEFile::Read(DWORD Offset, DWORD Size,char** s, int* slen)
{
	char* Address = (char*)handle->BaseAddress;
	if ((Offset + Size) >= handle->SizeOfImage)
	{
		*s = "";
		*slen = 0;
	}
	else
	{
		*s = (char*)malloc(Size);
		memcpy(*s,&Address[Offset],Size);
		*slen = Size;
	}
}

