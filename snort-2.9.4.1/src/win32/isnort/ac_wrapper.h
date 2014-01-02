#pragma once

#include "ahocorasick.h"
#include "rule.h"
#include "pcre.h"
#include "statistics.h"

#pragma comment(lib, "pcre.lib")

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

	void add(content* pcontent)
	{
		if(pcontent->_flow){
			_is_contain_pcre_contents = true;
		}

		for(extvector<content*>::iterator it = _contents.begin() ; it != _contents.end() ; it++){
			if(pcontent->_parent->ruleid == (*it)->_parent->ruleid){
				return;
			}
		}

		_contents.push_back(pcontent);
	}

public:
	extvector<content*> _contents;
	astr				_text;
	extmap<int, int>	_start_end_index_in_packet;
	bool				_is_contain_pcre_contents;
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
	ac_wrapper(void);
	virtual ~ac_wrapper(void);
		
	void add_rule(rule& r);
	void add_string( const std::string& r, void* data = NULL, bool is_case_insensitive = false );
	void print_active_states(void);
	int compile(void);
	pcre_statistics search(const astr& text);
		
public:
	time_statistics			_time_statistics;
	extvector<ac_item*>		_items;
	extmap<int, extvector<ac_item*>>	_items_by_rule; // key - ruleid ; value - ac_item*

private:
	ac_wrapper(const ac_wrapper&){}
	void operator =(const ac_wrapper&){}

	static const astr* _current_searched_text;

	AC_AUTOMATA_t * acap;
	AC_PATTERN_t	tmp_patt;
	AC_TEXT_t		tmp_text;

	static int match_found(AC_MATCH_t* m, void* param);
	pcre_statistics _search_statistics;
};
//-------------------------------------------------------------------------------

