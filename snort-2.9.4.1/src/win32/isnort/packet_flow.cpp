#include "StdAfx.h"
#include "packet_flow.h"
//-------------------------------------------------------------------------------
void packet_flow::add( int start_index, pcre_flow* _flow )
{
	if(!_packet_flow.is_exist(start_index)){
		_packet_flow.add(start_index, extvector<pcre_flow*>());
	}

	if(!_packet_flow[start_index].contains(_flow)){
		_packet_flow[start_index].push_back(_flow);
	}
}
//-------------------------------------------------------------------------------
void packet_flow::set_packet( const astr* packet )
{
	_packet = packet;
}
//-------------------------------------------------------------------------------
extvector<rule*> packet_flow::scan_full_matched_rules( void )
{
	extvector<rule*> matched;
	uint16_t curmask = 0;
	
	// while didn't scan whole packet flow
	while(_packet_flow.begin() != _packet_flow.end())
	{
		int current_index = _packet_flow.begin()->first;
		extvector<pcre_flow*>& index_flows = _packet_flow.begin()->second;

		// iterate the PCRE flows in the current exact string index
		bool is_redo = false;
		for(extvector<pcre_flow*>::iterator itflows = index_flows.begin() ; itflows != index_flows.end() || is_redo ; itflows++ )
		{
			if(is_redo)
			{
				is_redo = false;
				itflows--;
			}

			pcre_flow* curflow = *itflows;
			pcre_flow_node* current_flow_node = curflow->_current;

			// ignore match/mismatch PCREs
			if(curflow->_match_state != pcre_flow::none){
				continue;
			}

			// for each matching text, add to curmask the quantifier mask
			switch(current_flow_node->_type)
			{
				case pcre_flow_node::node_type_verify_quantifier:
				case pcre_flow_node::node_type_exact_string:
				{
					// check size of exact string
					int exact_string_length = current_flow_node->_exact_string.length();

					// check quantifier till this exact string or verification point
					if(current_flow_node->_prev && current_flow_node->_prev->_type == pcre_flow_node::node_type_quantifier)
					{
						#pragma region check quantifier till this exact string or verification point
						pcre_flow_node* prev_quanti_node = current_flow_node->_prev;

						// if there is an exact string before quantifier, get that index, else, start at 0.
						int index_to_check_quantifier = prev_quanti_node->_prev &&  prev_quanti_node->_prev->_type == pcre_flow_node::node_type_exact_string ?
																					prev_quanti_node->_prev->_exact_string_end_index_in_packet :
																					prev_quanti_node->_last_turn_on_index;

						
						int minimum_quanti_length = current_index - index_to_check_quantifier;
						if(!prev_quanti_node->_is_start_of_input && prev_quanti_node->_quantifier_range_start < minimum_quanti_length){
							minimum_quanti_length = prev_quanti_node->_quantifier_range_start;
						}

						int quantifier_length = get_quantifier_range(prev_quanti_node->_quantifier_group, current_index, minimum_quanti_length);

						// check if quantifier FAILED!
						if( quantifier_length < prev_quanti_node->_quantifier_range_start ||
							quantifier_length > prev_quanti_node->_quantifier_range_end)
						{
							// fallback the PCRE flow.
							// go back through all the quantifiers and look for the latest quantifier
							// that consumes all the strings from that last index to the current index.
							pcre_flow_node* fallback_quantifier_node = current_flow_node->_prev;
							if(fallback_quantifier_node->_type != pcre_flow_node::node_type_quantifier){
								throw std::exception("not CQC or QCQ!");
							}

							fallback_quantifier_node = fallback_quantifier_node->_prev_quantifier;

							bool done = false;
							while( fallback_quantifier_node && !done)
							{
								// if there is an exact string before quantifier, get that index, else, start at 0.
								int index_to_check_quantifier = fallback_quantifier_node->_prev &&  fallback_quantifier_node->_prev->_type == pcre_flow_node::node_type_exact_string ?
																							fallback_quantifier_node->_prev->_exact_string_end_index_in_packet :
																							fallback_quantifier_node->_last_turn_on_index;
								
								int minimum_quanti_length = current_index - index_to_check_quantifier;
								if(prev_quanti_node->_quantifier_range_start < minimum_quanti_length){
									minimum_quanti_length = prev_quanti_node->_quantifier_range_start;
								}

								quantifier_length = get_quantifier_range(fallback_quantifier_node->_quantifier_group, current_index, minimum_quanti_length);

								// quantifier does not match!
								if(quantifier_length == -1)
								{
									fallback_quantifier_node = fallback_quantifier_node ->_prev_quantifier;
									continue;
								}
								
								current_flow_node = fallback_quantifier_node->_next;
								break;
							}

							// if couldn't fallback - reset to the beginning
							if(!fallback_quantifier_node){
								current_flow_node = curflow->reset();
							}

							curflow->_current = current_flow_node;

							// if first exact string in the flow matches the current exact string,
							// then continue matching this exact string, otherwise, leave it in the
							// first flow.
							
							astr exact_string_in_packet(_packet->c_str()+current_index, current_flow_node->_exact_string.length() > _packet->length()-current_index ?
																				_packet->length()-current_index : current_flow_node->_exact_string.length());

							if(current_flow_node->_type == pcre_flow_node::node_type_exact_string &&
								current_flow_node->_exact_string == exact_string_in_packet)
							{
								// we can't just use curflow->next() because we need to set a new index
								// in the flow that points to the quantifier
								is_redo = true;
								continue;
							}
						}
#pragma endregion
					}

					// extract string from packet
					astr exact_string_in_packet;
					if(current_flow_node->_type == pcre_flow_node::node_type_exact_string)
					{
						exact_string_in_packet.assign(_packet->c_str()+current_index, current_flow_node->_exact_string.length() > _packet->length()-current_index ?
																						_packet->length()-current_index :
																						current_flow_node->_exact_string.length());
					}
					
					if(current_flow_node->_type == pcre_flow_node::node_type_verify_quantifier || exact_string_in_packet == current_flow_node->_exact_string) // Exact string matched
					{
						// keep exact string match 
						current_flow_node->_exact_string_end_index_in_packet = current_index + current_flow_node->_exact_string.length();

						if(!curflow->next()) // if there is no more - MATCH!
						{
							curflow->_match_state = pcre_flow::match;
							matched.push_back(&g_pcre_rules.get_rule_id(curflow->_ruleid));
						}
						else
						{
							current_flow_node = curflow->_current;

							if(current_flow_node->_type == pcre_flow_node::node_type_quantifier)
							{
								int end_of_exact_string = current_index + exact_string_length;

								// place the PCRE flow at the index of the end of the exact string
								if(!_packet_flow.is_exist(end_of_exact_string)){
									_packet_flow.add(end_of_exact_string, extvector<pcre_flow*>());
								}

								_packet_flow[end_of_exact_string].push_back(*itflows);
							}
						}
					}
					else // exact string does not match
					{
						if(current_flow_node->_prev_exact_string)
						{
							if(exact_string_in_packet.starts_with(current_flow_node->_prev_exact_string->_exact_string))
							{
								pcre_flow_node* prev_exact_string = current_flow_node->_prev_exact_string;
								bool is_fallback = false;

								// check that the quantifier before "_prev_exact_string" reaches
								// the current string.
								if(prev_exact_string->_prev)
								{
									if(prev_exact_string->_prev->_type != pcre_flow_node::node_type_quantifier){
										throw std::exception("not CQC!");
									}

									quanti_range& ranges = _quanti_ranges[prev_exact_string->_prev->_quantifier_group];

									if(ranges.is_last_set())
									{
										is_fallback = true;
									}
								}
								else
								{
									is_fallback = true;
								}

								if(is_fallback)
								{
									int new_prev_string_end_index = current_index + prev_exact_string->_exact_string.length();
									prev_exact_string->_exact_string_end_index_in_packet = new_prev_string_end_index;
									curflow->prev();

									_packet_flow[new_prev_string_end_index].push_back(curflow);
								}
							}
						}
					}

				}break;

				case pcre_flow_node::node_type_quantifier:
				{
					// add the mask
					curmask |= current_flow_node->_quantifier_group;
					
					quanti_range& quantir = _quanti_ranges[current_flow_node->_quantifier_group];
					if(!quantir.is_last_set())
					{
						quantir.set(current_index);
						current_flow_node->_last_turn_on_index = current_index;
					}

					curflow->next();
				}break;

				default:
					throw std::exception("Unexpected PCRE flow node type");
			}
		}

		// erase first item.
		_packet_flow.erase(_packet_flow.begin());

		if(curmask != 0 && _packet_flow.begin() != _packet_flow.end())
		{
			// if quantifier mask if not 0, scan until next index in flow.
			scan_quantifiers(curmask, current_index, _packet_flow.begin()->first-1);
		}
	}

	return matched;
}
//-------------------------------------------------------------------------------
bool packet_flow::is_quantifier_match_string( uint16_t quantimask, astr& input )
{	
	const char* pinput = input.c_str();
	int len = input.length();

	for(int i=0 ; i<len ; i++)
	{
		char c = *(pinput+i);

		if((g_flows._lookup_table[c] & quantimask) == 0)
		{
			return false;
		}
	}

	return true;
}
//-------------------------------------------------------------------------------
void packet_flow::scan_quantifiers( uint16_t& curmask, int start_index, int end_index )
{
	int count = end_index-start_index;

	const char* ppacket = _packet->c_str();
	
	for(int i=0 ; i<=count ; i++)
	{
		char c = *(ppacket+start_index+i);
		
		uint64_t missing_quantigroups = 0;
		
		// if some of the quanti-groups do not match
		if((missing_quantigroups = g_flows._lookup_table[c] ^ curmask) != 0)
		{			
			// remove quanti-groups that does not match from curmask
			curmask &= ~missing_quantigroups;

			for(int j=1 ; j<=sizeof(uint64_t)*8 ; j++)
			{
				// if group i has been removed
				uint16_t missing_bit = 0;
				if((missing_bit = get_bit(missing_quantigroups, j)) != 0)
				{
					// for each group that does not match, mark the reset index.
					_quanti_ranges[missing_bit].reset(start_index+i);
				}
			}

			/*
			 *	In the example alice[A-Z]+cooper:
			 *	aliceAaliceBalice9aliceZcooper
			 *	2nd and 3rd alices are being ignored because _last_set is 5
			 *	Because of "9", the _last_reset is 18, therefore when we get to the
			 *	last alice, we see that _last_reset > _last_set, therefore we reset.
			 */

			// if there are no more quantifier groups to check, finish scan.
			if(curmask == 0){
				break;
			}
		}
	}
}
//-------------------------------------------------------------------------------
void packet_flow::clear( void )
{
	_packet_flow.clear();
	_quanti_ranges.clear();
}
//-------------------------------------------------------------------------------
int packet_flow::get_quantifier_range( uint16_t _quantifier_group, int current_index, int minimum_quanti_length )
{
	quanti_range& ranges = _quanti_ranges[_quantifier_group];

	// calculate quantifier length
	/*
	int quantifier_length = ranges._last_reset > ranges._last_set || (ranges._last_reset == ranges._last_set && current_index != ranges._last_reset)?
		-1	:
		current_index - ranges._last_set; // matches *, ?, + and possibly {x}
	*/


	int quantifier_length = ranges.is_last_reset() ? ranges._last_reset == ranges._last_set ? 0 : -1
													 : current_index - ranges._last_set;

	// make sure that the length of the quantifier is at least the length from the current index,
	// to the index the quantifier should start from.
	if(quantifier_length < minimum_quanti_length){
		quantifier_length = -1;
	}

	return quantifier_length;
}
//-------------------------------------------------------------------------------