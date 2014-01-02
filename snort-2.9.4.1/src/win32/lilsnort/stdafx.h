// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>

#define _WINSOCKAPI_ 
#include <Windows.h>

#include <cpp_utilities\cstr.h>
#include <cpp_utilities\extmap.h>
#include <cpp_utilities\file.h>
#include <boost/program_options.hpp>

#ifdef _DEBUG
#pragma comment(lib, "cpp_utilities_dbg.lib")
#else
#pragma comment(lib, "cpp_utilities.lib")
#endif


// TODO: reference additional headers your program requires here
