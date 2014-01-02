#pragma once

#include "acsmx2.h"
#include "rule.h"
#include "pcre.h"

#ifdef _DEBUG
#pragma comment(lib, "pcred.lib")
#else
#pragma comment(lib, "pcre.lib")
#endif

//-------------------------------------------------------------------------------
struct pcre_statistics
{
	pcre_statistics():pcre_executions(0), pcre_matches(0){}
	pcre_statistics(const pcre_statistics& other){ *this = other; }

	void operator = (const pcre_statistics& other)
	{
		pcre_executions = other.pcre_executions;
		pcre_matches = other.pcre_matches;
	}

	void clear()
	{
		pcre_executions = 0;
		pcre_matches = 0;
	}
	
	int pcre_executions;
	int pcre_matches;
	extmap<int, int> pcre_matches_rules_count; // key - ruleid, value - match count
	extmap<int, int> pcre_exec_rules_count; // key - ruleid, value - match count
};
//-------------------------------------------------------------------------------
struct time_statistics
{
	time_statistics():_start(0){ _proc = ::GetCurrentProcess(); }

	void start()
	{	
		_start = ::GetTickCount();
	}

	void end()
	{
		if(_start == 0){
			throw std::exception("called end() before setting _start");
		}

		_execution_times.push_back(::GetTickCount() - _start);

		_start = 0;
	}

	double average(int packets_count)
	{
		if(_execution_times.size() == 0){
			return 0.0;
		}

		__int64 s = sum();

		return (double)s / (double)packets_count;
	}

	__int64 sum()
	{
		__int64 s = 0;

		for(int i=0 ; i<_execution_times.size() ; i++){
			s += _execution_times[i];
		}

		return s;
	}

private:
	HANDLE _proc;
	
	DWORD _start;
	extvector<DWORD> _execution_times;
};
//-------------------------------------------------------------------------------
class ac_item
{
public:
	ac_item(void):_is_contain_pcre_contents(false){}
	ac_item(const ac_item& other){ *this = other; }

	void operator = (const ac_item& other)
	{
		_contents = other._contents;
		_text = other._text;
		_start_end_index_in_packet = other._start_end_index_in_packet;
		_is_contain_pcre_contents = other._is_contain_pcre_contents;
	}
	
public:
	extvector<content*> _contents;
	astr				_text;
	extmap<int, int>	_start_end_index_in_packet;
	bool				_is_contain_pcre_contents;
};

/**
    Aho-Corasick 2 (casmx2) wrapper.
**/
class ac_wrapper
{
public:
	static pcre_statistics global_statistics;

public:
	ac_wrapper(void (*userfree)(void *p) = NULL, void (*optiontreefree)(void **p) = NULL, void (*neg_list_free)(void **p) = NULL);
	virtual ~ac_wrapper(void);

	property_get_set(DWORD, format);
	property_set(bool, is_verbose);
	
	void add_rule(rule& r);
	void print_active_states(void);
	int compile(int (*build_tree)(void * id, void **existing_tree) = NULL, int (*neg_list_func)(void *id, void **list) = NULL);
	pcre_statistics search(const astr& text, int (*fmatch)(void * id, void *tree, int index, void *data, void *neg_list) = NULL, int current_state = 0);

	operator ACSM_STRUCT2*(){ return _acsm; }

	time_statistics	_time_statistics;

private:
	ac_wrapper(const ac_wrapper&){}
	void operator =(const ac_wrapper&){}

	static const astr* _current_searched_text;

	ACSM_STRUCT2*	_acsm;
	static int match_found(void* id, void* tree, int index, void* data, void* neg_list);

	pcre_statistics _search_statistics;
	extvector<ac_item*>		_items;
};
//-------------------------------------------------------------------------------

