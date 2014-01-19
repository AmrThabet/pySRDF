// pySRDF.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "pySRDF.h"

Test::Test(char* str)
{
	x = (char*)malloc(strlen(str)+1);
	memset(x,0,strlen(str));
	memcpy(x,str,strlen(str));
}

Test::~Test()
{
	free(x);
}

int Test::AddString(char* str)
{
	x = (char*)malloc(strlen(str)+1);
	memset(x,0,strlen(str)+1);
	memcpy(x,str,strlen(str));
	return strlen(x);
}

void Test::GetValues()
{
	//TEST_STRUCT** y = (TEST_STRUCT**)malloc(sizeof(TEST_STRUCT*)*3);
	//arr.init(sizeof(TEST_STRUCT));
	cList* y = new cList(sizeof(TEST_STRUCT));
	TEST_STRUCT* x = (TEST_STRUCT*)malloc(sizeof(TEST_STRUCT)+1);
	memset(x,0,sizeof(TEST_STRUCT)+1);
	x->x = 50;
	x->y = 40;
	x->z = 30;

	//y[0] = x;
	y->AddItem((char*)x);
	TEST_STRUCT* z = (TEST_STRUCT*)malloc(sizeof(TEST_STRUCT)+1);
	memset(z,0,sizeof(TEST_STRUCT)+1);
	z->x = 500;
	z->y = 400;
	z->z = 300;
	y->AddItem((char*)z);
	//y[1] = z;

	//arr.setlength(2);
	//arr.setvalues(y);
	arr = (array<TEST_STRUCT*>)y;
	return;
}
char* print_to_python()
{
	return "Hello from C :)\n";
}

int _tmain(int argc, _TCHAR* argv[])
{
	cHash Amr;
	Amr.AddItem("Amr","Thabet");
	cout << Amr.Serialize() << "\n";
	return 0;
}

