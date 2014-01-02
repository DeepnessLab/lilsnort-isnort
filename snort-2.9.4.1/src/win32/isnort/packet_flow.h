#pragma once

//-------------------------------------------------------------------------------
struct quanti_range
{
	quanti_range(void):_last_set(0), _last_reset(0), _last_action(last_action_none){}
	enum last_action{last_action_set, last_action_reset, last_action_none};

	inline void set(int index)
	{
		_last_set = index;
		_last_action = last_action_set;
	}

	inline void reset(int index)
	{
		_last_reset = index;
		_last_action = last_action_reset;
	}

	inline bool is_last_set(){ return _last_action == last_action_set; }
	inline bool is_last_reset(){ return _last_action == last_action_reset; }

	int			_last_set;
	int			_last_reset;
	last_action	_last_action;
};
//-------------------------------------------------------------------------------
class packet_flow
{
public:
	packet_flow(void):_packet(NULL){}
	virtual ~packet_flow(void){}

	extvector<rule*> scan_full_matched_rules(void);
	void add( int start_index, pcre_flow* _flow );
	void set_packet( const astr* packet );
	void scan_quantifiers( uint16_t& curmask, int start_index, int end_index );
	bool is_quantifier_match_string( uint16_t quantimask, astr& input );
	void clear(void);	
	
private:
	extmap<int, extvector<pcre_flow*>>		_packet_flow;
	const astr* _packet;

	// key - quanti group ; value - quanti range
	extmap<uint16_t, quanti_range>	_quanti_ranges;

private:
	inline int get_quantifier_range( uint16_t _quantifier_group, int current_index, int minimum_quanti_length );
};
//-------------------------------------------------------------------------------