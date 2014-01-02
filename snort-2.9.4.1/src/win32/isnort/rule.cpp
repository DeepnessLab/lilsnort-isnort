#include "StdAfx.h"
#include "rule.h"
#include <sstream>


//-------------------------------------------------------------------------------
rule::~rule( void )
{
}
//-------------------------------------------------------------------------------
void rule::parse_rule()
{
	if(!_raw.starts_with("alert")){
		throw std::exception("not a rule");
	}

	extvector<astr> parts = _raw.split("; ");

	// loop through parts.
	for(int i=0 ; i<(int)parts.size() ; i++)
	{
		if(parts[i].starts_with("content:\"")) // if content
		{
			parse_content(parts[i]);
		}
		else if(parts[i].starts_with("pcre:\""))
		{
			_is_include_pcre = true;
			parse_pcre(parts[i]);
		}
		else if(parts[i].starts_with("sid:"))
		{
			astr strruleid = parts[i];
			strruleid.replace_all("sid:", "");
			std::istringstream((std::string)strruleid) >> _ruleid;
		}
		else if(parts[i].starts_with("nocase"))
		{
			_nocase = true;
		}
	}
}
//-------------------------------------------------------------------------------
astr rule::to_string()
{
	astr res = astr::format("ruleid: %d\r\n", ruleid);
	for(int i=0 ; i<(int)_contents.size() ; i++)
	{
		res += astr::format("content %d: \"%s\"", i, _contents[i]._text.c_str());
		if(i+1<(int)_contents.size()){
			res += "\r\n";
		}
	}

	if(_is_include_pcre){
		res += astr::format("\r\npcre: \"%s\"", _regex.c_str());
	}

	return res;
}
//-------------------------------------------------------------------------------
void rule::parse_content( astr content_text )
{
	content_text.erase(0, 9); // delete 'content:"' text
	content_text.erase(content_text.length()-1); // delete last character (which is '"');
	
	extvector<astr> strbyteslist = content_text.split_brackets("|", "|");
	for(int i=0 ; i<(int)strbyteslist.size() ; i++)
	{
		astr strbytes = strbyteslist[i];
		strbytes.replace_all(" ", "");
		astr res;
		for(int j=0 ; j<(int)strbytes.size() ; j+=2)
		{
			astr temp = strbytes.at(j);
			temp += strbytes.at(j+1);
			int b;
			std::stringstream iss;
			iss << std::hex << (std::string)temp;
			iss >> b;
			res += (char)b;
		}

		content_text.replace_all(strbyteslist[i], res); // replace string-bytes in content attribute.
	}

	// remove all '|'
	content_text.replace_all("|", "");

	_contents.push_back(content(this, _contents.size()+1, content_text));
}
//-------------------------------------------------------------------------------
bool rule::get_matched( void ) const
{
	for(int i=0 ; i<(int)_contents.size() ; i++)
	{
		if(!_contents[i]._matched){
			return false;
		}
	}

	return true;
}
//-------------------------------------------------------------------------------
void rule::clear_matches()
{
	for(int i=0 ; i<(int)_contents.size() ; i++){
		_contents[i]._matched = false;
	}
	
	_flow->reset();
}
//-------------------------------------------------------------------------------
void rule::operator=( const rule& other )
{
	_contents = other._contents;
	_is_include_pcre = other._is_include_pcre;
	_raw = other._raw;
	_ppcre = other._ppcre;
	_ruleid = other._ruleid;
	_ppcre_extra = other._ppcre_extra;
	_regex = other._regex;
	_nocase = other._nocase;
	_flow = other._flow;
	_exact_pcre_contents_finding = other._exact_pcre_contents_finding;

	for(int i=0 ; i<(int)_contents.size() ; i++){
		_contents[i]._parent = (rule*)this;
	}
}
//-------------------------------------------------------------------------------
void rule::parse_pcre( astr strpcre )
{
	strpcre.erase(0, 7); // delete 'pcre:"/' text
	strpcre.erase(strpcre.length()-1); // delete last character (which is '"');

	astr options = strpcre.substr(strpcre.rfind('/'));
	strpcre.erase(strpcre.length()-options.length());
	options.erase(0, 1); // delete delimiter '/'

	int pcre_options = 0;

	for(int i=0 ; i<(int)options.length() ; i++)
	{
		switch(options.at(i))
		{
			case 'i':  pcre_options |= PCRE_CASELESS;            break;
			case 's':  pcre_options |= PCRE_DOTALL;              break;
			case 'm':  pcre_options |= PCRE_MULTILINE;           break;
			case 'x':  pcre_options |= PCRE_EXTENDED;            break;
		
				/*
				 * these are pcre specific... don't work with perl
				 */
			case 'A':  pcre_options |= PCRE_ANCHORED;            break;
			case 'E':  pcre_options |= PCRE_DOLLAR_ENDONLY;      break;
			case 'G':  pcre_options |= PCRE_UNGREEDY;            break;
		}
	}

	_regex = strpcre;

	// compile pcre
	char err[1024] = {0};
	int errcode = 0;
	int offset = 0;
	_ppcre = pcre_compile2(_regex.c_str(), pcre_options, &errcode, (const char**)&err, &offset, NULL);
	if(_ppcre == NULL)
	{
		throw std::exception(astr::format("Failed to compile PCRE \"%s\". ruleid: %d", _regex.c_str(), _ruleid));
	}

	_ppcre_extra = pcre_study(_ppcre, NULL, (const char**)&err);
}
//-------------------------------------------------------------------------------
rule::rule( const astr& raw )
	:_raw(raw), _is_include_pcre(false), _nocase(false), _ppcre(NULL), _ppcre_extra(NULL), _flow(NULL)
{
	// load content
	parse_rule();
}
//-------------------------------------------------------------------------------
void rule::add_pcre_flow( pcre_flow* pflow )
{
	_flow = pflow;
	
	// load exact pcre strings into content
	int index_in_flow = 0;
	do
	{
		if(pflow->_current->_type == pcre_flow_node::node_type_exact_string)
		{
			bool found = false;
			for(extvector<content>::iterator it = _contents.begin() ; it != _contents.end() ; it++)
			{
				if(it->_text == pflow->_current->_exact_string)
				{
					found = true;
					it = _contents.erase(it);
					if(it != _contents.begin()){
						it--;
					}

					_contents.insert(it, content(this, _contents.size()+1, pflow->_current->_exact_string, index_in_flow, pflow));
					break;
				}
			}

			if(!found){
				_contents.push_back(content(this, _contents.size()+1, pflow->_current->_exact_string, index_in_flow, pflow));
			}
		}

		index_in_flow++;
	}
	while(pflow->next());

	pflow->reset();
}
//-------------------------------------------------------------------------------