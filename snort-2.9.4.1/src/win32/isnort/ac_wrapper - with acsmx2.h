#pragma once

#include "acsmx2.h"
#include "rule.h"
#include "pcre.h"
#include "statistics.h"

#pragma comment(lib, "pcre.lib")

//-------------------------------------------------------------------------------
class ac_item
{
public:
	ac_item(void){}
	ac_item(const ac_item& other){ *this = other; }

	void operator = (const ac_item& other)
	{
		_contents = other._contents;
		_text = other._text;
		_start_end_index_in_packet = other._start_end_index_in_packet;
	}

public:
	extvector<content*> _contents;
	astr				_text;
	extmap<int, int>	_start_end_index_in_packet;
};
//-------------------------------------------------------------------------------
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
	void add_string( const std::string& r, void* data = NULL, bool is_case_insensitive = false );
	void print_active_states(void);
	int compile(int (*build_tree)(void * id, void **existing_tree) = NULL, int (*neg_list_func)(void *id, void **list) = NULL);
	pcre_statistics search(const astr& text, int (*fmatch)(void * id, void *tree, int index, void *data, void *neg_list) = NULL, int current_state = 0);

	operator ACSM_STRUCT2*(){ return _acsm; }
	
public:
	time_statistics			_time_statistics;
	extvector<ac_item*>		_items;
	extmap<int, extvector<ac_item*>>	_items_by_rule; // key - ruleid ; value - ac_item*

private:
	ac_wrapper(const ac_wrapper&){}
	void operator =(const ac_wrapper&){}

	static const astr* _current_searched_text;

	ACSM_STRUCT2*	_acsm;
	static int match_found(void* id, void* tree, int index, void* data, void* neg_list);
	pcre_statistics _search_statistics;
};
//-------------------------------------------------------------------------------

