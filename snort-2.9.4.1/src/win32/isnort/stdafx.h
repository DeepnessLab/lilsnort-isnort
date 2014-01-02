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
#include <cpp_utilities\extvector.h>
#include <cpp_utilities\file.h>
#include <boost/program_options.hpp>

#ifdef _DEBUG
#pragma comment(lib, "cpp_utilities_dbg.lib")
#else
#pragma comment(lib, "cpp_utilities.lib")
#endif

#include "pcre_flow.h"
#include "ac_wrapper.h"
#include "rules_collection.h"

extern pcre_flows					g_flows;
extern ac_wrapper					g_ac;
extern rule_collection				g_pcre_rules;
extern extvector<pcre_statistics>	g_packets_search_results;
extern time_statistics				g_pcre_analysis_time_stat;
extern time_statistics				g_packet_flow_time_stat;
extern time_statistics				g_ac_stat;
extern pcre_executed_counter		g_pcre_executed_counter;
extern extmap<ac_item*, bool>		g_found_acitems;

#define set_bit(num, i)		num |= (1LL << (i-1))
#define clear_bit(num, i)	(num &= ~(1LL << (i-1)))
#define toggle_bit(num, i)	num ^= (1LL << (i-1))
#define get_bit(num, i)		(num & (1LL << (i-1)))