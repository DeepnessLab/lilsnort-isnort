#pragma once

//-------------------------------------------------------------------------------
struct pcre_executed_counter
{
public:
	pcre_executed_counter(){}
	~pcre_executed_counter(){}

	void add(int count)
	{
		_counts.push_back(count);
	}

	int sum(void)
	{
		int s = 0;

		for(int i=0 ; i<(int)_counts.size() ; i++){
			s += _counts[i];
		}

		return s;
	}

	double average(void)
	{
		if(_counts.size() == 0){
			return 0.0;
		}

		int s = sum();

		return (double)s / (double)_counts.size();
	}

	extvector<int> _counts;
};
//-------------------------------------------------------------------------------
struct pcre_statistics
{
	pcre_statistics():pcre_executions(0), pcre_matches(0){}
	pcre_statistics(const pcre_statistics& other){ *this = other; }

	void operator = (const pcre_statistics& other)
	{
		pcre_executions = other.pcre_executions;
		pcre_matches = other.pcre_matches;
		pcre_matches_rules_count = other.pcre_matches_rules_count;
		pcre_exec_rules_count = other.pcre_exec_rules_count;
	}

	void clear()
	{
		pcre_executions = 0;
		pcre_matches = 0;
		pcre_matches_rules_count.clear();
		pcre_exec_rules_count.clear();
	}

	void add_execute(int ruleid)
	{
		if(pcre_exec_rules_count.is_exist(ruleid)){
			pcre_exec_rules_count[ruleid]++;
		}
		else{
			pcre_exec_rules_count.add(ruleid, 1);
		}
	}

	void add_matches(int ruleid)
	{
		if(pcre_matches_rules_count.is_exist(ruleid)){
			pcre_matches_rules_count[ruleid]++;
		}
		else{
			pcre_matches_rules_count.add(ruleid, 1);
		}
	}
	
	int pcre_executions;
	int pcre_matches;
	extmap<int, int> pcre_matches_rules_count; // key - ruleid, value - match count
	extmap<int, int> pcre_exec_rules_count; // key - ruleid, value - match count
};
//-------------------------------------------------------------------------------
struct time_statistics
{
	time_statistics():_start(0){ _proc = ::GetCurrentProcess(); }

	void start()
	{	
		_start = ::GetTickCount();
	}

	void end()
	{
		if(_start == 0){
			throw std::exception("called end() before setting _start");
		}

		_execution_times.push_back(::GetTickCount() - _start);

		_start = 0;
	}

	double average(int packets_count)
	{
		if(_execution_times.size() == 0){
			return 0.0;
		}

		__int64 s = sum();

		return (double)s / (double)packets_count;
	}

	__int64 sum()
	{
		__int64 s = 0;

		for(int i=0 ; i<(int)_execution_times.size() ; i++){
			s += _execution_times[i];
		}

		return s;
	}

private:
	HANDLE _proc;
	
	DWORD _start;
	extvector<DWORD> _execution_times;
};
//-------------------------------------------------------------------------------