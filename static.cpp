// static.cpp : includes all static search and check like yara scanner, ssdeep and md5
//

#include "stdafx.h"
#include "pySRDF.h"

YaraScanner::YaraScanner()
{
	YaraScan = new cYaraScanner();
}

void YaraScanner::AddRule(char* Name, char* Rule)
{
	cString Signature = Rule;
	Signature.Replace(':',' ');
	cString NewRule = YaraScan->CreateRule(Name,Signature);
	YaraScan->AddRule(NewRule);
}

array<YARA_SEARCH*> YaraScanner::Search(char* buff, DWORD size)
{
	unsigned char* Address = (unsigned char*)buff;
	array<YARA_SEARCH*> found;
	found.init(sizeof(YARA_SEARCH));

	if (Address == NULL)return found;
	cList* Results = YaraScan->Scan(Address,size);
	if (Results == NULL)return found;
	
	for (int i = 0; i < Results->GetNumberOfItems();i++)
	{
		_YARA_RESULT* Result = (_YARA_RESULT*)Results->GetItem(i);

		for (int l = 0; l < Result->Matches->GetNumberOfItems();l++)
		{
			YARA_SEARCH item = {0};
			MSTRING* Match = (MSTRING*)Result->Matches->GetItem(l);
			//cout << "FOUND RULE: " << Result->RuleIdentifier << "\t" << (int*)(Match->offset) << "\n";
			item.Offset = Match->offset;
			item.Name = Result->RuleIdentifier;
			found.additem(&item);
		}
	}

	return found;
}

YaraScanner::~YaraScanner()
{
	delete YaraScan;
}

//===================
//SSDeep


char* ssdeep(char* buff, DWORD size)
{
	SSDeep ssdeep;
	if (size == 0)size = strlen(buff);

	cString r = ssdeep.Hash((const unsigned char *)buff,size);
	char* s = (char*)malloc(r.GetLength());
	memcpy(s,r.GetChar(),r.GetLength());
	return s;
}

DWORD ssdeepcompare(char* sig1, char* sig2)
{
	SSDeep ssdeep;
	return ssdeep.Compare(sig1,sig2);
}

//===================
//MD5

char* md5(char* buff,DWORD size)
{
	if (size == 0)size = strlen(buff);
	cMD5String* md5 = new cMD5String();

	md5->Encrypt(buff,size);
	return *md5;
}