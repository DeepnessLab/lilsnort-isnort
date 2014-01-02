#include "StdAfx.h"
#include "ac_wrapper.h"

const astr* ac_wrapper::_current_searched_text = NULL;
pcre_statistics ac_wrapper::global_statistics;

//-------------------------------------------------------------------------------
ac_wrapper::ac_wrapper(void)
{
	acap = ac_automata_init(ac_wrapper::match_found);
}
//-------------------------------------------------------------------------------
ac_wrapper::~ac_wrapper(void)
{
	ac_automata_release(acap);
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
				_items[j]->add(cnt);
				
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
			pitem->add(cnt);
			pitem->_text = cnt->_text;

			_items.push_back(pitem);

			if(!_items_by_rule.is_exist(r.ruleid)){
				_items_by_rule.add(r.ruleid, extvector<ac_item*>());
			}

			_items_by_rule[r.ruleid].push_back(pitem);
			
			tmp_patt.astring = const_cast<char*>(cnt->_text.c_str());
			tmp_patt.rep.number = reinterpret_cast<unsigned long>(pitem);
			tmp_patt.length = cnt->_text.length();
			ac_automata_add(acap, &tmp_patt);
		}
	}
}
//-------------------------------------------------------------------------------
void ac_wrapper::add_string( const std::string& str, void* /*data*/ /*= NULL*/, bool /*is_case_insensitive*/ /*= false*/)
{
	tmp_patt.astring = const_cast<char*>(str.c_str());
	//tmp_patt.rep.number = i+1; // optional
	tmp_patt.length = str.length();
	ac_automata_add(acap, &tmp_patt);
}
//-------------------------------------------------------------------------------
int ac_wrapper::compile( void )
{
	ac_automata_finalize(acap);
	return 0;
}
//-------------------------------------------------------------------------------
pcre_statistics ac_wrapper::search( const astr& text )
{
	_current_searched_text = &text;
	_search_statistics.clear();

	ac_automata_reset(acap);

	tmp_text.astring = const_cast<char*>(text.c_str());
	tmp_text.length = text.length();

	ac_automata_search(acap, &tmp_text, 0);

	//_time_statistics.end();
	return _search_statistics;
}
//-------------------------------------------------------------------------------
extmap<ac_item*, bool> g_found_acitems;
int ac_wrapper::match_found( AC_MATCH_t* m, void* /*param*/ )
{
	// for all ac_items in this current index
	// (for instance "alice" and "ice" ends in the same index)
	for (unsigned int i=0; i < m->match_num; i++)
	{
		AC_PATTERN_t& match = m->patterns[i];
		ac_item* item = (ac_item*)match.rep.number;
		
		if(item->_is_contain_pcre_contents){
			item->_start_end_index_in_packet.add(m->position-item->_text.length(), m->position);
		}

		// If its the first time we get this "string", check if it matches the rule
		// for every ac_item check once it is matched.
		if(!g_found_acitems.is_exist(item))
		{
			g_found_acitems.add(item, true);

			for(extvector<content*>::iterator it = item->_contents.begin() ; it != item->_contents.end() ; it++)
			{
				content* ct = *it;
				ct->_matched = true;
				rule* prule = ct->_parent;
				
				if(prule->matched)
				{
					g_pcre_rules._content_matched_rules.push_back(prule);
				}
			}
		}
	}

	return 0;
}
//-------------------------------------------------------------------------------