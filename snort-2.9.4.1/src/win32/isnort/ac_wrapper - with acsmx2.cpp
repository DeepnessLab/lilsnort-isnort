#include "StdAfx.h"
#include "ac_wrapper.h"

const astr* ac_wrapper::_current_searched_text = NULL;
pcre_statistics ac_wrapper::global_statistics;

//-------------------------------------------------------------------------------
ac_wrapper::ac_wrapper(void (*userfree)(void *p) /*= NULL*/, void (*optiontreefree)(void **p) /*= NULL*/, void (*neg_list_free)(void **p) /*= NULL*/)
{
	_acsm = acsmNew2(userfree, optiontreefree, neg_list_free);
}
//-------------------------------------------------------------------------------
ac_wrapper::~ac_wrapper(void)
{
	acsmFree2(_acsm);
}
//-------------------------------------------------------------------------------
DWORD ac_wrapper::get_format( void ) const
{
	return _acsm->acsmFormat;
}
//-------------------------------------------------------------------------------
void ac_wrapper::set_format( const DWORD& val )
{
	_acsm->acsmFormat = val;
}
//-------------------------------------------------------------------------------
void ac_wrapper::add_rule( rule& r )
{
	for(int i=0 ; i<(int)r.contents.size() ; i++)
	{
		content* cnt = &(r.contents[i]);

		bool is_found = false;
		size_t j = 0;
		for(j=0 ; j<_items.size() ; j++)
		{
			if(_items[j]->_text == cnt->_text)
			{
				_items[j]->_contents.push_back(cnt);
				
				is_found = true;
				break;
			}
		}

		if(is_found)
		{
			if(!_items_by_rule.is_exist(r.ruleid)){
				_items_by_rule.add(r.ruleid, extvector<ac_item*>());
			}

			_items_by_rule[r.ruleid].push_back(_items[j]);
		}
		else
		{
			// new ac_item
			ac_item* pitem = new ac_item();
			pitem->_contents.push_back(cnt);
			pitem->_text = cnt->_text;

			_items.push_back(pitem);

			if(!_items_by_rule.is_exist(r.ruleid)){
				_items_by_rule.add(r.ruleid, extvector<ac_item*>());
			}

			_items_by_rule[r.ruleid].push_back(pitem);
			acsmAddPattern2(_acsm, (unsigned char*)cnt->_text.c_str(), cnt->_text.length(), r.nocase ? 1 : 0, 0, 0, 0, (void*)pitem, r.ruleid);
		}
	}
}
//-------------------------------------------------------------------------------
void ac_wrapper::add_string( const std::string& str, void* data /*= NULL*/, bool is_case_insensitive /*= false*/)
{
	acsmAddPattern2(_acsm, (unsigned char*)str.c_str(), str.length(), is_case_insensitive ? 1 : 0, 0, 0, 0, data, 0);
}
//-------------------------------------------------------------------------------
void ac_wrapper::set_is_verbose( const bool& is_verbose )
{
	acsmSetVerbose2(is_verbose);
}
//-------------------------------------------------------------------------------
void ac_wrapper::print_active_states( void )
{
	Print_DFA(_acsm);
}
//-------------------------------------------------------------------------------
int ac_wrapper::compile( int (*build_tree)(void * id, void **existing_tree) /*= NULL*/, int (*neg_list_func)(void *id, void **list) /*= NULL*/ )
{
	return acsmCompile2(_acsm, build_tree, neg_list_func);
}
//-------------------------------------------------------------------------------
pcre_statistics ac_wrapper::search( const astr& text, int (*fmatch)(void * id, void *tree, int index, void *data, void *neg_list) /*= NULL*/, int current_state /*= 0*/ )
{
	_current_searched_text = &text;
	_search_statistics.clear();

	//_time_statistics.start();
	if(fmatch){
		acsmSearch2(_acsm, (unsigned char*)text.c_str(), text.size(), fmatch, this, &current_state);
	}
	else{
		acsmSearch2(_acsm, (unsigned char*)text.c_str(), text.size(), ac_wrapper::match_found, this, &current_state);
	}
	//_time_statistics.end();
	return _search_statistics;
}
//-------------------------------------------------------------------------------
int ac_wrapper::match_found( void* id, void* /*tree*/, int index, void* data, void* /*neg_list*/ )
{
	ac_item* item = (ac_item*)id;

	item->_start_end_index_in_packet.add(index, index+item->_text.length());

	// If its the first time we get this "string", check if it matches the rule
	// for every ac_item check once it is matched.
	if(item->_start_end_index_in_packet.size() == 1)
	{
		for(extvector<content*>::iterator it = item->_contents.begin() ; it != item->_contents.end() ; it++)
		{
			content* ct = *it;
			ct->_matched = true;
			rule* prule = ct->_parent;

			if(ct->_parent->matched){
				g_pcre_rules._content_matched_rules.push_back(ct->_parent);
			}
		}
	}

	return 0;
}
//-------------------------------------------------------------------------------