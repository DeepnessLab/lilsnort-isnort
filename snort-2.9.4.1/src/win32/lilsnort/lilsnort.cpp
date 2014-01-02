// lilsnort.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "rules_collection.h"
#include "rule.h"
#include "ac_wrapper.h"
#include "pcap_reader.hpp"

using namespace gfutilities;
using namespace text;
using namespace data_structures;
using namespace io;
 namespace po = boost::program_options;

#define RULES_FILE L".\\..\\..\\..\\..\\rules\\not_commented_no_ors_chosen_rules.rules"
#define PCAP_FILE  ".\\..\\..\\..\\..\\inputs\\not_commented_content_only_attack_packet_1000packets.pcap"
#define LINE_LEN 16



rule_collection load_pcre_rules(const wstr& filename);
void			dispatcher_handler(u_char *, const struct pcap_pkthdr *, const u_char *);
void			init_ac(void);

ac_wrapper					ac;
rule_collection				pcre_rules;
extvector<pcre_statistics>	packets_search_results;

enum statistics_type{stats_type_time, stats_type_count};

void take_statistics( statistics_type stats_type ) 
{
	if(stats_type == stats_type_time)
	{
		// Take time statistics
		printf("Time taken in average for AC: %fms\r\n", ac._time_statistics.average(packets_search_results.size()));
		printf("Total time spent for AC: %dms\r\n", ac._time_statistics.sum());
	}
	else if(stats_type == stats_type_count)
	{
		// per-packet statistics
		double average_pcre_per_packet_exec = 0;
		double average_pcre_per_packet_match = 0;
		for(int i=0 ; i<(int)packets_search_results.size() ; i++)
		{
			average_pcre_per_packet_exec += packets_search_results[i].pcre_executions;
			average_pcre_per_packet_match += packets_search_results[i].pcre_matches;
		}

		// Average PCRE statistics
		average_pcre_per_packet_exec /= packets_search_results.size();
		average_pcre_per_packet_match /= packets_search_results.size();
		printf("Average PCRE execution per packet: %3.2f\r\n", average_pcre_per_packet_exec);
		printf("Average PCRE matches per packet: %3.2f\r\n", average_pcre_per_packet_match);


		// total statistics
		double pcre_machings = ((double)ac_wrapper::global_statistics.pcre_matches / (double)ac_wrapper::global_statistics.pcre_executions)*100.0;
		printf("PCRE total executions: %d\r\n", ac_wrapper::global_statistics.pcre_executions);
		printf("PCRE total matches: %d\r\n", ac_wrapper::global_statistics.pcre_matches);
		printf("PCRE matchings out of PCRE executions: %3.2f%%\r\n", pcre_machings);

		// write CSV with match counts
		printf("calculating PCRE exec counts\r\n");
		wstr csv;
		extmap<int, int>& pcre_exec_count = ac_wrapper::global_statistics.pcre_exec_rules_count;
		for(extmap<int, int>::iterator it = pcre_exec_count.begin() ; it != pcre_exec_count.end() ; it++){
			csv += wstr::format(L"%d,%d\r\n", it->first, it->second);
		}		
//		file fcsv(L".\\..\\..\\..\\..\\pcre_exec.csv");
//		fcsv.open(GENERIC_ALL, NULL, CREATE_ALWAYS);
//		fcsv.write(csv);
//		fcsv.flush();
//		fcsv.close();
	}
	else
	{
		throw std::exception("Unexpected stats type");
	}
}
//-------------------------------------------------------------------------------
class packet_handler
{
public:
	packet_handler(ac_wrapper* pac):_pac(pac){}

	void operator()(const astr& packet)
	{
		pcre_rules.clear_rules();

		try
		{
			packets_search_results.push_back(_pac->search(packet));
		}
		catch(const std::exception& err)
		{
			printf("Error has occured while searching %s", err.what());
		}
	}

private:
	ac_wrapper* _pac;
};
//-------------------------------------------------------------------------------
int _tmain(int /*argc*/, _TCHAR* /*argv*/[])
{
	try
	{
		wstr strname = L"20_cqc_pcres";
		wstr inputname = L"20_cqc_pcres";
		astr pcapname = "20_cqc_pcres";

		wstr rules_file = L".\\..\\..\\..\\..\\rules\\"+strname+L".rules";
		wstr input_file = L".\\..\\..\\..\\..\\inputs\\"+inputname+L"_content_attack_packet.txt";
		astr pcap_file = ".\\..\\..\\..\\..\\inputs\\"+pcapname+".pcap";

		if(!file::is_exist(rules_file))
		{
			wprintf(wstr::format(L"Cannot find rules file: %s\r\n", rules_file.c_str()));
			return 1;
		}

		pcre_rules = load_pcre_rules(rules_file);
		printf("Loaded PCRE %d rules\r\n", pcre_rules.size());

		init_ac();

		packet_handler packet_functor(&ac);

		// load file
		file f(input_file);
		astr input;
		f.read(input);
		for(int i=0 ; i<1000 ; i++){
			packet_functor(input);
		}

		// load packet
		/*
		pcap_reader<packet_handler> preader(pcap_file, &packet_functor);
		printf("Matching...\r\n");
		preader.start_parse();
		*/

		take_statistics(stats_type_time);

		printf("done\r\n");
		return 0;
	}
	catch(std::exception& err)
	{
		printf("Fatal error has occured %s", err.what());
	}

	return 1;
}
//-------------------------------------------------------------------------------
rule_collection load_pcre_rules( const wstr& filename )
{
	astr all_rules;
	file finput(filename.c_str());
	finput.read(all_rules);
	finput.close();

	rule_collection pcre_rules;
	all_rules.replace_all("\r", "");
	extvector<astr> strrules = all_rules.split("\n", true);
	for(int i=0 ; i<(int)strrules.size() ; i++)
	{
		try
		{
			astr& strrule = strrules[i];
			if(strrule.starts_with("alert") && strrule.contains("pcre:\""))
			{
				rule r(strrule);
				pcre_rules.push_back(rule(strrule));
			}
		}
		catch(const std::exception& err)
		{
			printf("ERROR parsing rule: %s\r\n", err.what());
		}
	}

	return pcre_rules;
}
//-------------------------------------------------------------------------------
void init_ac() 
{
	ac.is_verbose = false;
	ac.format = ACF_FULL;

	printf("Adding patterns to AC...\r\n");
	for(int i=0 ; i<(int)pcre_rules.size() ; i++){
		ac.add_rule(pcre_rules[i]);
	}

	printf("Compiling AC...\r\n");
	ac.compile();
}
//-------------------------------------------------------------------------------