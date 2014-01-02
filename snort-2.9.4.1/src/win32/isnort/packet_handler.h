#pragma once
#include "packet_flow.h"

//-------------------------------------------------------------------------------
class packet_handler
{
public:
	packet_handler(ac_wrapper* pac):_pac(pac){}

	void operator()(const astr* packet);
	void clear(void);

private:
	ac_wrapper* _pac;
	packet_flow	_packet_flow;
};
//-------------------------------------------------------------------------------