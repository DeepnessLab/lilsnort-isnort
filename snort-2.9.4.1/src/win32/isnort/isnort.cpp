// lilsnort.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "rule.h"
#include "pcap_reader.hpp"
#include "pcre_flow.h"
#include "packet_handler.h"

using namespace gfutilities;
using namespace text;
using namespace data_structures;
using namespace io;
namespace po = boost::program_options;

#define LINE_LEN 16

enum statistics_type{stats_type_time, stats_type_count};

void load_pcre_rules(const wstr& filename);
void dispatcher_handler(u_char *, const struct pcap_pkthdr *, const u_char *);
void init_ac(void);
void take_statistics( statistics_type stats_type );

ac_wrapper					g_ac;
rule_collection				g_pcre_rules;
extvector<pcre_statistics>	g_packets_search_results;
time_statistics				g_pcre_analysis_time_stat;
time_statistics				g_packet_flow_time_stat;
time_statistics				g_ac_stat;
pcre_executed_counter		g_pcre_executed_counter;

//-------------------------------------------------------------------------------
void exec_packet(astr& packet)
{
	astr inputs_path = "inputs\\";

	packet_handler packet_functor(&g_ac);
	pcap_reader<packet_handler> preader(inputs_path+packet, &packet_functor);
	preader.start_parse();
}
//-------------------------------------------------------------------------------
void exec_file(wstr& fname)
{
	wstr inputs_path = L"inputs\\";

	packet_handler packet_functor(&g_ac);
	file f(inputs_path+fname);
	astr input;
	f.read(input);
	f.close();
	packet_functor(&input);
}
//-------------------------------------------------------------------------------
void load_rules(const wstr& rfiles)
{
	wstr rules_path = L"rules\\";
	wstr pcre_xml = rules_path + rfiles + L".xml";
	wstr rules_file = rules_path + rfiles + L".rules";

	// load PCRE XML
	file fxml(pcre_xml);
	astr pcresxml;
	fxml.read(pcresxml);

	// generate flows
	printf("creating PCRE flows\r\n");
	g_flows.init(pcresxml);

	load_pcre_rules(rules_file);
	printf("Loaded PCRE %d rules\r\n", g_pcre_rules.size());

	init_ac();


	printf("adding rule's to aho-corasick\r\n");
	for(int i=0 ; i<(int)g_pcre_rules.size() ; i++){
		g_ac.add_rule(g_pcre_rules[i]);
	}

	// compile
	g_ac.compile();

	// load packet
	packet_handler packet_functor(&g_ac);
}
//-------------------------------------------------------------------------------
void exec_test(wstr& rules_file, astr& packet)
{
	load_rules(rules_file);

	printf("executing: %s\r\n", packet.c_str());
	exec_packet(packet);
}
//-------------------------------------------------------------------------------
void exec_test(wstr& rules_file, wstr& fname)
{
	load_rules(rules_file);

	printf("executing: %S\r\n", fname.c_str());
	for(int i=0 ; i<1000 ; i++){
		exec_file(fname);
	}
}
//-------------------------------------------------------------------------------
void exec_test_string(wstr& rules_file, astr& str)
{
	load_rules(rules_file);

	printf("executing\r\n");
	
	packet_handler packet_functor(&g_ac);
	packet_functor(&str);
}
//-------------------------------------------------------------------------------
void exec_unitests(void)
{
	load_rules(L"cqc_tests");

	packet_handler packet_functor(&g_ac);

	#pragma region unit tests

		// parse test input
		astr input1("alice cooper"); // match
		astr input2("alice     cooper"); // match
		astr input3("alice  3   cooper"); // no match
		astr input4("alice  3   alice        cooper"); // match
		astr input4b("alice  3   alice    5   cooper"); // no match
		astr input5("alice   alice         cooper"); // match
		astr input5b("alice   alice  4      cooper"); // no match
		astr input5c("alice   alice   alice      cooper"); // match
		astr input6("bla bla alice         cooper"); // match
		astr input6b("bla bla alice   5     cooper"); // no match
		astr input7("bla cooper alice         cooper"); // match
		astr input7b("bla cooper alice      4  cooper"); // no match
		astr input8("alicecooper"); // match

		astr input11("aliceAcooper"); // match
		astr input12("aliceAAAAAcooper"); // match
		astr input13("aliceAAAA999AAAAcooper"); // no match
		astr input14("aliceAAAA3AAAAaliceAAAAAAAAAcooper"); // match
		astr input14b("aliceAAAA3AAAAAaliceAAAAA5AAAAAcooper"); // no match
		astr input15("aliceAAAAAaliceAAAAAAAAAAAcooper"); // match
		astr input15b("aliceAAAAAAAaliceAAAA444AAAAAAAAAcooper"); // no match
		astr input16("blaAblaAaliceAAAAAAAAAAAAAcooper"); // match
		astr input16b("blaAblaAaliceA5AAAAAcooper"); // no match
		astr input17("blaAcooperAaliceAAAAAAAAAAAAcooper"); // match
		astr input17b("blaAcooperAaliceAAAAAA4AAcooper"); // no match
		
		astr input20("alice cooper aliceAAAcooper"); // matches 1111 and 2222

		astr input21("alice444cooper"); // match
		astr input22("alice4444cooper"); // no match
		astr input23("alice444alice444cooper"); // match

		astr input30("alice cooper aliceAAAcooper alice999cooper"); // matches 1111 and 2222 and 3333
		
		astr input31("onethreetwofour"); // matches 4444, 5555
		astr input32("one two three two three four"); // matches 4444, 5555, 6666

		astr input41("onexxxtwoxxxthree four"); // matches 7777
		astr input42("onexxxtwoxxxone999twoxxxthree four"); // matches 7777

		astr input50("one   yosi   david    two    shimi"); // no match
		astr input51("one two  yosi   david        shimi"); // matches 8888 and 9999
		astr input52("onetwo  yosidavidshimi"); // matches 8888 and 9999

#define runtest(testname)	printf("\r\n-------\r\n%s: \"%s\"\r\n", #testname, testname.c_str()); \
							packet_functor(&testname);
		
		runtest(input1);
		runtest(input2);
		runtest(input3);
		runtest(input4);
		runtest(input4b);

		runtest(input5);
		runtest(input5b);
		runtest(input5c);

		runtest(input6);
		runtest(input6b);
		runtest(input7);
		runtest(input7b);
		runtest(input8);
		
		runtest(input11);
		runtest(input12);
		runtest(input13);
		runtest(input14);
		runtest(input14b);
		runtest(input15);
		runtest(input15b);
		runtest(input16);
		runtest(input16b);
		runtest(input17);
		runtest(input17b);

		runtest(input20);

		runtest(input21);
		runtest(input22);
		runtest(input23);
		
		runtest(input30);

		runtest(input31);
		runtest(input32);
		
		runtest(input41);
		runtest(input42);
		
		runtest(input50);
		runtest(input51);
		runtest(input52);
	
#pragma endregion
};
//-------------------------------------------------------------------------------
int _tmain(int /*argc*/, _TCHAR* /*argv*/[])
{
	try
	{
		::SetCurrentDirectory(L".\\..\\..\\..\\..\\");
		
		
		//exec_unitests();
		exec_test(wstr(L"cqc_qcq_without_or"), wstr(L"cqc_qcq_without_or_content_attack_packet.txt"));
		//exec_test(wstr(L"isnort_wins"), astr("first_content_only_attack_packet_1000packets.pcap"));
		//exec_test_string(wstr(L"not_commented_no_ors_chosen_rules"), astr("aaatestme     "));

		printf("g_pcre_analysis_time_stat (actual PCRE execution): %dms\r\n", g_pcre_analysis_time_stat.sum());
		printf("g_packet_flow_time_stat (packet flow construction): %dms\r\n", g_packet_flow_time_stat.sum());
		printf("g_ac (aho-corasick): %dms\r\n", g_ac_stat.sum());
		printf("g_pcre_executed_counter: %d\r\n", g_pcre_executed_counter.sum());

		printf("total: %dms\r\n", g_packet_flow_time_stat.sum() + g_pcre_analysis_time_stat.sum() + g_ac_stat.sum());
	}
	catch(std::exception& err)
	{
		printf("Fatal error has occured %s", err.what());
	}

	return 1;
}
//-------------------------------------------------------------------------------
void load_pcre_rules( const wstr& filename )
{
	astr all_rules;
	file finput(filename.c_str());
	finput.read(all_rules);
	finput.close();

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
				r.add_pcre_flow(g_flows._flows[r.ruleid]);
				g_pcre_rules.push_back(r);
			}
		}
		catch(const std::exception& err)
		{
			printf("ERROR parsing rule: %s\r\n", err.what());
		}
	}
}
//-------------------------------------------------------------------------------
void init_ac() 
{
	printf("Adding patterns to AC...\r\n");
	for(int i=0 ; i<(int)g_pcre_rules.size() ; i++){
		g_ac.add_rule(g_pcre_rules[i]);
	}

	printf("Compiling AC...\r\n");
	g_ac.compile();
}
//-------------------------------------------------------------------------------