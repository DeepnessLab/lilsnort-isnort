#include "StdAfx.h"
#include "ac_wrapper.h"
#include <regex>

const astr* ac_wrapper::_current_searched_text = NULL;
pcre_statistics ac_wrapper::global_statistics;
extvector<int> g_executed_rules;

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
		content* cnt = (content*)&(r.contents[i]);

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

		if(!is_found)
		{
			// new ac_item
			ac_item* pitem = new ac_item();
			pitem->_contents.push_back(cnt);
			pitem->_text = cnt->_text;

			_items.push_back(pitem);

			acsmAddPattern2(_acsm, (unsigned char*)pitem->_text.c_str(),pitem->_text.length(), r.nocase ? 1 : 0, 0, 0, 0, (void*)pitem, r.ruleid);
		}
	}
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
	g_executed_rules.clear();
	
	_time_statistics.start();
	if(fmatch){
		acsmSearch2(_acsm, (unsigned char*)text.c_str(), text.size(), fmatch, this, &current_state);
	}
	else{
		acsmSearch2(_acsm, (unsigned char*)text.c_str(), text.size(), ac_wrapper::match_found, this, &current_state);
	}
	_time_statistics.end();
	return _search_statistics;
}
//-------------------------------------------------------------------------------
int ac_wrapper::match_found( void* id, void* /*tree*/, int index, void* data, void* /*neg_list*/ )
{
	ac_item* pitem = (ac_item*)id;

	for(extvector<content*>::iterator it = pitem->_contents.begin() ; it != pitem->_contents.end() ; it++)
	{
		content* cnt = (content*)*it;
		pcre_statistics* search_statistics = &(((ac_wrapper*)data)->_search_statistics); // per-search statistics
		time_statistics* ptime_statistics = &(((ac_wrapper*)data)->_time_statistics);

		int rid = cnt->_parent->ruleid;

		// set content as matched
		cnt->_matched = true;

		// full content match - check PCRE
		if(cnt->_parent->matched && !g_executed_rules.contains(rid))
		{
			g_executed_rules.push_back(rid);
			//printf("execution %d\r\n", g_executed_rules.size());

			int subs[9] = {0};

			int res = pcre_exec(cnt->_parent->ppcre, cnt->_parent->ppcre_extra, _current_searched_text->c_str(), _current_searched_text->length(), 0, NULL, subs, 9);

			search_statistics->pcre_executions++;
			ac_wrapper::global_statistics.pcre_executions++;

			if(ac_wrapper::global_statistics.pcre_exec_rules_count.is_exist(cnt->_parent->ruleid)){
				ac_wrapper::global_statistics.pcre_exec_rules_count[cnt->_parent->ruleid]++;
			}
			else{
				ac_wrapper::global_statistics.pcre_exec_rules_count.add(cnt->_parent->ruleid, 1);
			}

			if(res > PCRE_ERROR_NOMATCH)
			{
				//printf("FULL+PCRE match: %d\r\n", cnt->_parent->ruleid);
				search_statistics->pcre_matches++;
				ac_wrapper::global_statistics.pcre_matches++;

				if(ac_wrapper::global_statistics.pcre_matches_rules_count.is_exist(cnt->_parent->ruleid)){
					ac_wrapper::global_statistics.pcre_matches_rules_count[cnt->_parent->ruleid]++;
				}
				else{
					ac_wrapper::global_statistics.pcre_matches_rules_count.add(cnt->_parent->ruleid, 1);
				}
			}
		}
	}
		
	return 0;
}
//-------------------------------------------------------------------------------