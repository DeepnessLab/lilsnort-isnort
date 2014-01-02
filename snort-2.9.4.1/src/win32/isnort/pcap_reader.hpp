#pragma once

#include <pcap.h>
#pragma comment(lib, "wpcap.lib")

//-------------------------------------------------------------------------------
template<typename F>
class pcap_reader
{
public:
	pcap_reader(const astr& fcap, F* cb):_pcap_filename(fcap){ _cb_functor = cb; }
	virtual ~pcap_reader(void){}

	void start_parse(void);

private:
	static void dispatcher_handler(u_char* temp1, const struct pcap_pkthdr* header, const u_char* pkt_data);

private:
	astr		_pcap_filename;
	static F*	_cb_functor;
};
//-------------------------------------------------------------------------------
template<typename F>
F* pcap_reader<F>::_cb_functor = NULL;
//-------------------------------------------------------------------------------
template<typename F>
void pcap_reader<F>::dispatcher_handler( u_char* /*temp1*/, const struct pcap_pkthdr* header, const u_char* pkt_data )
{
	astr p((char*)pkt_data, header->caplen);
	(*_cb_functor)(&p);
}
//-------------------------------------------------------------------------------
template<typename F>
void pcap_reader<F>::start_parse( void )
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* fp = pcap_open_offline(_pcap_filename, errbuf);

	pcap_loop(fp, 0, pcap_reader::dispatcher_handler, NULL);

	pcap_close(fp);
}
//-------------------------------------------------------------------------------