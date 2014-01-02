#include "StdAfx.h"
#include "packet_handler.h"

//-------------------------------------------------------------------------------

/**
    operator casting operator.
**/
void packet_handler::operator()( const astr* packet )
{
	clear();
	
	g_ac_stat.start();
	// pass 1
	g_ac.search(*packet);

	g_ac_stat.end();

	// pass 2
	_packet_flow.set_packet(packet);

	g_pcre_executed_counter.add(g_pcre_rules._content_matched_rules.size());
	
	g_packet_flow_time_stat.start();
	// go over all matched rules, for each matched rule
	// add PCRE_Flow to each packet index one of the rules exists in.
	for(extvector<rule*>::iterator rule_it = g_pcre_rules._content_matched_rules.begin() ; rule_it  != g_pcre_rules._content_matched_rules.end() ; rule_it++)
	{
		rule* currule = *rule_it;
		bool is_exact_string_must_start_at_beginning = currule->_flow->_pstart->_is_start_of_input && currule->_flow->_pstart->_type == pcre_flow_node::node_type_exact_string;
		bool is_exact_string_at_beginning_exists = false;

		// if rule's PCRE ends with quantifier, place verify node at the end.
		if(currule->_flow->_plast->_type == pcre_flow_node::node_type_verify_quantifier){
			_packet_flow.add(packet->length(), currule->_flow);
		}

		// for all the matched rules, get start index from AC items and place the pcre_flow
		extvector<ac_item*>& items = _pac->_items_by_rule[currule->ruleid];
		int first_ac_item_index_in_packet = INT_MAX;
		for(extvector<ac_item*>::iterator item_it = items.begin() ; item_it != items.end() ; item_it++)
		{
			ac_item* cur_ac_item = *item_it;

			// iterate the appearences of the item
			for(extmap<int, int>::iterator start_index_it = cur_ac_item->_start_end_index_in_packet.begin() ; start_index_it != cur_ac_item->_start_end_index_in_packet.end() ; start_index_it++)
			{
				if(is_exact_string_must_start_at_beginning && start_index_it->first == 0){
					is_exact_string_at_beginning_exists = true;
				}

				_packet_flow.add(start_index_it->first, currule->_flow);

				if(start_index_it->first < first_ac_item_index_in_packet){
					first_ac_item_index_in_packet = start_index_it->first;
				}
			}
		}

		// if PCRE starts with "^" and no content starts at index "0", then there is no match.
		// THIS IS TRUE ONLY FOR CQC rules
		if(is_exact_string_must_start_at_beginning && !is_exact_string_at_beginning_exists && currule->_flow->_is_supported_pcre)
		{
			currule->_flow->_match_state = pcre_flow::mismatch;
		}

		// if rule's PCRE starts with quantifier
		if(currule->_flow->_pstart->_type == pcre_flow_node::node_type_quantifier)
		{
			// if start of input, place at index 0.
			if(currule->_flow->_pstart->_is_start_of_input)
			{
				_packet_flow.add(0, currule->_flow);
			}
			else
			{
				if(currule->_flow->_pstart->_next->_type != pcre_flow_node::node_type_exact_string){
					throw std::exception("not CQC or QCQ");
				}

				int quanti_index = first_ac_item_index_in_packet;
				quanti_index--;

				_packet_flow.add(quanti_index, currule->_flow);
			}
		}
	}
	g_packet_flow_time_stat.end();

	g_pcre_analysis_time_stat.start();
	extvector<rule*> full_matched = _packet_flow.scan_full_matched_rules();
	g_pcre_analysis_time_stat.end();

	for(extvector<rule*>::iterator it_matched = full_matched.begin() ; it_matched != full_matched.end() ; it_matched++)
	{
		printf("Full match ruleID: %d \"%s\"\r\n", (*it_matched)->ruleid, (*it_matched)->regex.c_str());
	}
}
//-------------------------------------------------------------------------------
void packet_handler::clear( void )
{
	g_pcre_rules.clear_rules();
	_packet_flow.clear();
	g_flows.reset_flows();
	g_found_acitems.clear();

	for(extvector<ac_item*>::iterator it = g_ac._items.begin() ; it != g_ac._items.end() ; it++){
		(*it)->_start_end_index_in_packet.clear();
	}
}
//-------------------------------------------------------------------------------
