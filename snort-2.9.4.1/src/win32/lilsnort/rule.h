#pragma once
#include <cpp_utilities/properties.h>
#include <cpp_utilities/cstr.h>
#include <cpp_utilities/extvector.h>
#include "pcre.h"

using namespace gfutilities;
using namespace data_structures;
using namespace text;

class rule;

//-------------------------------------------------------------------------------
struct content
{
	content(rule* parent, int index, const astr& text):_parent(parent), _index(index), _text(text), _matched(false){}
	content(const content& other){ *this = other; }
	
	void operator = (const content& other)
	{
		_index = other._index;
		_text = other._text;
		_parent = other._parent;
		_matched = other._matched;
	}

	int		_index;
	astr	_text;
	rule*	_parent;
	bool	_matched;
};
//-------------------------------------------------------------------------------
class rule
{
public:
	rule(const astr& raw):_raw(raw), _is_include_pcre(false), _nocase(false), _ppcre(NULL), _ppcre_extra(NULL){ parse_rule(); }
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
	property_get_implemented(const extvector<content>&, contents);
	property_get(bool, matched);

	astr to_string();
	void clear_matches();

protected:
	void parse_rule();
	void parse_content( astr content_text );
	void parse_pcre( astr pcre );

private:
	extvector<content>	_contents;
	bool				_is_include_pcre;
	astr				_raw;
	astr				_regex;
	pcre*				_ppcre;
	pcre_extra*			_ppcre_extra;
	int					_ruleid;
	bool				_nocase;
};
//-------------------------------------------------------------------------------
