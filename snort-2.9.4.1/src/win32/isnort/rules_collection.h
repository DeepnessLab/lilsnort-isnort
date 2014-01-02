#pragma once
#include <cpp_utilities\extvector.h>
#include "rule.h"

class rule_collection : public extvector<rule>
{
public:
	rule_collection(){}
	//-------------------------------------------------------------------------------
	void clear_rules()
	{
		for(rule_collection::iterator it = begin() ; it != end() ; it++){
			it->clear_matches();
		}

		_content_matched_rules.clear();
	}
	//-------------------------------------------------------------------------------
	extvector<rule*> get_all_matched_rules()
	{
		return _content_matched_rules;
	}
	//-------------------------------------------------------------------------------
	rule& get_rule_id(int ruleid)
	{
		for(size_t i=0 ; i<this->size() ; i++){
			if((*this)[i].ruleid == ruleid){
				return (*this)[i];
			}
		}

		throw std::exception("rule not found");
	}
	//-------------------------------------------------------------------------------

public:
	extvector<rule*> _content_matched_rules;
};