// pySRDF.cpp : this file is for general declarations
//

#include "stdafx.h"
#include "pySRDF.h"

int swig_c_error_num = 0;
char swig_c_err_msg[256];

const char *err_occurred()
{
    if (swig_c_error_num) {
        swig_c_error_num = 0;
        return (const char*)swig_c_err_msg;
    }
    return NULL;
}

void set_err(const char *msg)
{
    swig_c_error_num = 1;
    strncpy(swig_c_err_msg, msg, 256);
}

void addattr(PEFile* obj,char* name, char* value)
{

}


