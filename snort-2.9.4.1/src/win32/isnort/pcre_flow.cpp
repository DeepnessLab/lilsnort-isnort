#include "StdAfx.h"
#include "pcre_flow.h"
#include <regex>

using namespace pugi;
using namespace gfutilities;
using namespace text;
using namespace data_structures;
using namespace io;

pcre_flows g_flows;




//-------------------------------------------------------------------------------
//-----------------   pcre_flows implementation   -------------------------------
//-------------------------------------------------------------------------------
void pcre_flows::init( const astr& pcres_xml )
{
	xml_document pcres_doc;
	pcres_doc.load(pcres_xml.c_str());

	// load lookup
	xpath_node_set pcre_lookup = pcres_doc.select_nodes("/PCRES/LOOKUP/ENTRY");
	for(xpath_node_set::const_iterator it = pcre_lookup.begin() ; it != pcre_lookup.end() ; it++)
	{
		uint64_t val;
		std::stringstream ss;
		ss << it->node().attribute("lookup_value").as_string();
		ss >> val;

		_lookup_table[it->node().attribute("char").as_int()] = val;
	}

	// load quantifier groups
	xpath_node_set pcre_quantgroup = pcres_doc.select_nodes("/PCRES/QUANTIFIERGROUPS/QUANTIFIERGROUP");
	_quantifiers.push_back("dummy");
	for(xpath_node_set::const_iterator it = pcre_quantgroup.begin() ; it != pcre_quantgroup.end() ; it++){
		_quantifiers.push_back(it->node().attribute("string").as_string());
	}
	
	// iterate PCREs and create pcre flows
	xpath_node_set pcres = pcres_doc.select_nodes("/PCRES/PCRE");
	for(xpath_node_set::const_iterator it = pcres.begin() ; it != pcres.end() ; it++)
	{
		xml_node node = it->node();
		std::stringstream ss;
		node.print(ss);
		astr nodexml = ss.str();
		pcre_flow* pflow = new pcre_flow(nodexml);

		// for each PCRE build flow
		_flows.add(pflow->_ruleid, pflow);
	}
}
//-------------------------------------------------------------------------------
extvector<int> pcre_flows::get_supported_rules( void )
{
	extvector<int> res;

	// find CQC rules
	for(extmap<int, pcre_flow*>::iterator it = _flows.begin() ;
		it != _flows.end() ;
		it++)
	{
		if(it->second->_is_supported_pcre){
			res.push_back(it->first);
		}
	}

	return res;
}
//-------------------------------------------------------------------------------
void pcre_flows::reset_flows( void )
{
	for(extmap<int, pcre_flow*>::iterator it = _flows.begin() ; it != _flows.end() ; it++)
	{
		it->second->reset();
		it->second->_match_state = pcre_flow::none;
	}
}
//-------------------------------------------------------------------------------
void pcre_flow::build_flow( const astr& pcre_xml )
{
	xml_document pcre_doc;
	pcre_doc.load(pcre_xml.c_str());

	_ruleid = pcre_doc.first_child().attribute("ruleid").as_int();

	// iterate the children, and build flow
	xml_object_range<xml_node_iterator> children = pcre_doc.first_child().children();
	for(xml_node_iterator it = children.begin() ; it != children.end() ; it++){
		parse_node(*it);
	}

	_plast = _current;
	_current = _pstart; // set current to the starting point

	if(_plast->_type == pcre_flow_node::node_type_quantifier)
	{
		_plast->_next = new pcre_flow_node(pcre_flow_node::node_type_verify_quantifier);
		_plast->_next->_prev = _plast;
		_plast = _plast->_next;
	}

	// check if supported (CQC or QCQ)
	pcre_flow_node* cur = _pstart;
	_is_supported_pcre = true;
	while(cur != NULL && cur->_next && _is_supported_pcre)
	{
		if(cur->_type == pcre_flow_node::node_type_verify_quantifier)
		{
			cur = cur->_next;
			continue;
		}

		if(cur->_type == cur->_next->_type) // CC or QQ
		{
			_is_supported_pcre = false;
			break;
		}
		else // CQ or QC
		{
			cur = cur->_next;
		}
	}
}
//-------------------------------------------------------------------------------
void pcre_flow::parse_node( pugi::xml_node& cur_root )
{
	astr curname = cur_root.name();

	pcre_flow_node* n = NULL;

	if(curname == "LITERAL")
	{
		// make literal node
		n = new pcre_flow_node(pcre_flow_node::node_type_exact_string);
		astr literaltext = cur_root.attribute("text").as_string();
		
		std::regex re("\\\\x[0-9a-zA-Z]{2}");
		std::match_results<std::string::const_iterator> mr;
		if(std::regex_search(literaltext, mr, re))
		{
			for(int i=0 ; i<(int)mr.size() ; i++)
			{
				astr matchstr = mr[i];
				matchstr.replace_all("\\x", "");
				
				char* temp = NULL;
				byte b = strtol(matchstr.c_str(), &temp, 16);

				literaltext.replace_all(astr(mr[i]), astr(1, (char)b));
			}
		}

		n->_exact_string = literaltext;

		// add to string_to_rule
		if(!g_flows._string_to_rule.is_exist(n->_exact_string)){
			g_flows._string_to_rule.add(n->_exact_string, extvector<int>());
		}
		g_flows._string_to_rule[n->_exact_string].push_back(_ruleid);


	}
	else if(curname == "QUANTIFIER")
	{
		// make quantifier node
		n = new pcre_flow_node(pcre_flow_node::node_type_quantifier);
		int bit_to_set = cur_root.attribute("lookup_match_index").as_int();
		set_bit(n->_quantifier_group, bit_to_set);
		n->_quantifier_range_start = cur_root.attribute("start").as_int();
		n->_quantifier_range_end = astr("INF") == cur_root.attribute("end").as_string() ?	MAXINT :
																							cur_root.attribute("end").as_int();
	}
	else if(curname == "CAPTURING_GROUP")
	{
		xml_object_range<xml_node_iterator> children = cur_root.children();
		for(xml_node_iterator it = children.begin() ; it != children.end() ; it++){
			parse_node(*it);
		}

		// do not add this node to the flow - "parse_node()" adds
		// the node's children to the flow.
		return;
	}
	else if(curname == "START_OF_SUBJECT")
	{
		_next_node_start_of_subject = true;
		return;
	}
	else
	{
		throw std::exception(astr::format("expected node %s", curname.c_str()));
	}

	if(_next_node_start_of_subject)
	{
		n->_is_start_of_input = true;
		_next_node_start_of_subject = false;
	}

	if(!_pstart)
	{
		_pstart = n;
		_current = _pstart;
	}
	else
	{
		_current->_next = n;
		pcre_flow_node* prev = _current;
		_current = n;
		_current->_prev = prev;

		// set prev quantifier
		if(_current->_type == pcre_flow_node::node_type_quantifier)
		{
			pcre_flow_node* prev_quantifier = _current->_prev;
			
			while(prev_quantifier && prev_quantifier->_type != pcre_flow_node::node_type_quantifier){
				prev_quantifier = prev_quantifier->_prev;
			}

			_current->_prev_quantifier = prev_quantifier;
		}
		else if(_current->_type == pcre_flow_node::node_type_exact_string)
		{
			pcre_flow_node* prev_exact_string = _current->_prev;

			while(prev_exact_string && prev_exact_string->_type != pcre_flow_node::node_type_exact_string){
				prev_exact_string = prev_exact_string->_prev;
			}

			_current->_prev_exact_string = prev_exact_string;
		}
		else
		{
			throw std::exception("unknown node type");
		}
	}
}
//-------------------------------------------------------------------------------