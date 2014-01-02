#pragma once

#include "c:\Libraries\pugixml\src\pugixml.hpp"
#include "c:\Libraries\pugixml\src\pugiconfig.hpp"

using namespace pugi;
using namespace gfutilities;
using namespace text;
using namespace data_structures;

//-------------------------------------------------------------------------------
class pcre_flow_node
{
public:
	enum node_type{ node_type_exact_string, node_type_quantifier, node_type_verify_quantifier };

public:
	pcre_flow_node(node_type type):_next(NULL), _prev(NULL), _prev_quantifier(NULL), _prev_exact_string(NULL), _last_turn_on_index(0),
									_type(type), _is_start_of_input(false), _quantifier_group(0), _exact_string_end_index_in_packet(-1){}
	pcre_flow_node(const pcre_flow_node& other){ *this = other; }
	virtual ~pcre_flow_node(void){}

	void operator = (const pcre_flow_node& other)
	{
		_type = other._type;
		_exact_string = other._exact_string;
		_quantifier_group = other._quantifier_group;
		_quantifier_range_start = other._quantifier_range_start;
		_quantifier_range_end = other._quantifier_range_end;
		_is_start_of_input = other._is_start_of_input;
		_next = other._next;
		_prev_quantifier = other._prev_quantifier;
		_last_turn_on_index = other._last_turn_on_index;
	}

public:
	node_type		_type;
	astr			_exact_string;
	int				_exact_string_end_index_in_packet;
	uint16_t		_quantifier_group;
	int				_quantifier_range_start;
	int				_quantifier_range_end;
	bool			_is_start_of_input;
	int				_last_turn_on_index;
	pcre_flow_node*	_next;
	pcre_flow_node*	_prev;
	pcre_flow_node*	_prev_quantifier; // only for quantifier nodes.
	pcre_flow_node*	_prev_exact_string; // only for exact string nodes.
};
//-------------------------------------------------------------------------------
class pcre_flow
{
public:
	enum match_state{ none, match, mismatch };

public:
	pcre_flow(const astr& pcre_xml):_pstart(NULL), _plast(NULL), _current(_pstart),
									_ruleid(0), _is_supported_pcre(false), _match_state(none),
									_next_node_start_of_subject(false)
	{ 
		build_flow(pcre_xml);
	}

	virtual ~pcre_flow(void)
	{
		pcre_flow_node* cur = _pstart;

		while(cur != NULL)
		{
			pcre_flow_node* next = cur->_next;
			delete cur;
			cur = next;
		}
	}
	
	pcre_flow_node* reset(void)
	{ 
		_current = _pstart;
		return _current;
	}
	
	void clear()
	{
		pcre_flow_node* cur = _pstart;

		while(cur != NULL)
		{
			cur->_exact_string_end_index_in_packet = -1;
			cur->_last_turn_on_index = 0;
			cur = cur->_next;
		}
		
		reset();
	}

	bool next(void)
	{
		if(!_current->_next){
			return false;
		}

		_current = _current->_next;
		return true;
	}

	bool prev(void)
	{
		if(!_current->_prev){
			return false;
		}

		_current = _current->_prev;
		return true;
	}

private:
	void build_flow(const astr& pcre_xml);
	void parse_node(pugi::xml_node& cur_root);

public:
	int		_ruleid;
	bool	_is_supported_pcre; // is supported by flow

	pcre_flow_node* _pstart;
	pcre_flow_node* _plast;
	pcre_flow_node* _current;

	match_state	_match_state;

private:
	bool	_next_node_start_of_subject;
};
//-------------------------------------------------------------------------------
class pcre_flows
{
public:
	pcre_flows(void){ ZeroMemory(_lookup_table, sizeof(_lookup_table)); }
	virtual ~pcre_flows(void)
	{
		// TODO: delete all pcre_flow*
		// TODO even better: use smart pointer for pcre_flow
	}

	void init(const astr& pcres_xml);
	extvector<int> get_supported_rules(void);
	void reset_flows(void);
	
public:
	extmap<astr, extvector<int>>	_string_to_rule; // key - exact string, value - rules string in
	extmap<int, pcre_flow*>			_flows; // key - ruleid, value - flow
	uint64_t						_lookup_table[256]; // lookup table
	extvector<astr>					_quantifiers; // index - lookup_match_index in XML, value - quantifier group
};
//-------------------------------------------------------------------------------