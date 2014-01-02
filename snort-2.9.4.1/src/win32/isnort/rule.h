#pragma once
#include <cpp_utilities/properties.h>
#include <cpp_utilities/cstr.h>
#include <cpp_utilities/extvector.h>
#include "pcre.h"

using namespace gfutilities;
using namespace data_structures;
using namespace text;

class rule;

#define content_type_content		1
#define content_type_pcre_string	2

//-------------------------------------------------------------------------------
struct content
{
	content(rule* parent, int index, const astr& text, int index_in_pcre = 0, pcre_flow* flow = NULL):
		_parent(parent),_index(index), _text(text), _matched(false), _index_in_pcre(index_in_pcre), _flow(flow){}
	content(const content& other){ *this = other; }
	
	void operator = (const content& other)
	{
		_index = other._index;
		_text = other._text;
		_parent = other._parent;
		_matched = other._matched;
		_index_in_pcre = other._index_in_pcre;
		_flow = other._flow;
	}

	int			_index;
	astr		_text;
	bool		_matched;
	int			_index_in_pcre;
	pcre_flow*	_flow;
	rule*		_parent;
};
//-------------------------------------------------------------------------------
class rule
{
public:
	rule(const astr& raw);
	rule(const rule& other){ *this = other; }
	virtual ~rule(void);

	void operator = (const rule& other);

	property_get_implemented(bool, is_include_pcre);
	property_get_implemented(int, ruleid);
	property_get_implemented(const astr&, raw);
	property_get_implemented(const astr&, regex);
	property_get_implemented(pcre*, ppcre);
	property_get_implemented(pcre_extra*, ppcre_extra);
	property_get_implemented(bool, nocase);
	property_get_implemented_not_const(extvector<content>&, contents);
	property_get(bool, matched);

	astr to_string();
	void clear_matches();
	
	void parse_rule();
	void parse_content( astr content_text );
	void parse_pcre( astr pcre );
	void add_pcre_flow(pcre_flow* flow);

	extvector<content>	_contents;
	bool				_is_include_pcre;
	astr				_raw;
	astr				_regex;
	pcre*				_ppcre;
	pcre_extra*			_ppcre_extra;
	int					_ruleid;
	bool				_nocase;
	pcre_flow*			_flow;
	extmap<int, content*>	_exact_pcre_contents_finding; // key - start index in packet, value - content*
};
//-------------------------------------------------------------------------------
