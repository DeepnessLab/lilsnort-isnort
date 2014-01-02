#pragma once
#include <cpp_utilities\extvector.h>
#include "rule.h"

class rule_collection : public extvector<rule>
{
public:
	rule_collection(){}

	void clear_rules()
	{
		for(int i=0 ; i<(int)size() ; i++){
			(*this)[i].clear_matches();
		}
	}

	rule_collection get_all_matched_rules()
	{
		rule_collection matched;
		for(int i=0 ; i<(int)size() ; i++)
		{
			if((*this)[i].matched){
				matched.push_back((*this)[i]);
			}
		}

		return matched;
	}
};