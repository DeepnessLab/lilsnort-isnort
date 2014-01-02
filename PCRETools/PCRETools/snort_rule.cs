using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Wintellect.PowerCollections;

namespace PCRETools
{
    class snort_rule
    {
        private string raw = "";
        public string Raw { get { return raw; } }

        private List<string> contents = new List<string>();
        public string[] Contents { get { return contents.ToArray(); } }

        private string pcre = "";
        public string PCRE { get { return pcre; } }

        private List<string> pcre_exact_string = new List<string>();
        public string[] ExactStrings { get { return pcre_exact_string.ToArray(); } }

        public string[] AllExactStrings
        {
            get
            {
                Set<string> contentset = new Set<string>(contents);
                contentset.UnionWith(new Set<string>(pcre_exact_string));

                return contentset.ToArray();
            }
        }

        public int PriceByContent
        {
            get
            {
                int price = 0;
                foreach (string c in contents)
                    price += c.Length;

                return price;
            }
        }

        public int PriceByExactStrings
        {
            get
            {
                int price = 0;
                string[] all_exact_strings = AllExactStrings;
                foreach (string c in all_exact_strings)
                    price += c.Length;

                return price;
            }
        }

        private bool isFileData = false;
        public bool IsFileData { get { return isFileData; } }

        private bool isFlowBits = false;
        public bool IsFlowBits { get { return isFlowBits; } }

        private int within = -1;
        public int WithIn { get { return within; } }

        private int distance = -1;
        public int Distance { get { return distance; } }

        private int sid = 0;
        public int ID { get { return sid; } }

        //--------------------------------------------------------------------------------
        public snort_rule(string ruletext, string pcre_xml)
        {
            raw = ruletext;

            parse_content();

            parse_pcre(pcre_xml);

            isFileData = raw.Contains(" file_data; ");

            parse_within();

            parse_distance();

            parse_id();

            parse_flowbits();
        }
        //--------------------------------------------------------------------------------
        private void parse_flowbits()
        {
            isFlowBits = raw.Contains("; flowbits:");
        }
        //--------------------------------------------------------------------------------
        private void parse_id()
        {
            string strrule = Regex.Match(raw, " sid:([0-9]+); ").Groups[1].Value;
            sid = int.Parse(strrule);
        }
        //--------------------------------------------------------------------------------
        private void parse_distance()
        {
            if (Regex.IsMatch(raw, " distance:([0-9]+); "))
            {
                string strdistance = Regex.Match(raw, " distance:([0-9]+); ").Groups[1].Value;
                distance = int.Parse(strdistance);
            }
        }
        //--------------------------------------------------------------------------------
        private void parse_within()
        {
            if (Regex.IsMatch(raw, " within:([0-9]+); "))
            {
                Match m = Regex.Match(raw, " within:([0-9]+); ");
                string strwithin = m.Groups[1].Value;
                within = int.Parse(strwithin);
            }
        }
        //--------------------------------------------------------------------------------
        private void parse_pcre(string pcrexml)
        {
            int start = raw.IndexOf(" pcre:\"/") + " pcre:\"/".Length;
            pcre = raw.Substring(start, raw.IndexOf("\"; ", start) - start);
            pcre = pcre.Remove(pcre.LastIndexOf("/"));

            if (pcrexml != "")
            {
                pcre_xml pxml = new pcre_xml(pcrexml);
                pcre_exact_string.AddRange(pxml.Literals);
            }
        }
        //--------------------------------------------------------------------------------
        private void parse_content()
        {
            MatchCollection matches = Regex.Matches(raw, "content:\"");
            foreach (Match m in matches)
            {
                int start = m.Index + "content:\"".Length;
                string cnt = raw.Substring(start, raw.IndexOf("\"; ", start) - start);
                MatchCollection bytesmatch = Regex.Matches(cnt, "\\|([a-fA-F0-9 ]+)\\|");
                foreach(Match bm in bytesmatch)
                {
                    string[] strbytes = bm.Groups[1].Value.Split(new string[] { " " }, StringSplitOptions.RemoveEmptyEntries);
                    string res = "";

                    foreach(string strbyte in strbytes)
                    {
                        res += Convert.ToChar(Convert.ToInt32(strbyte, 16));
                    }

                    cnt = cnt.Replace(bm.Value, res);
                }

                contents.Add(cnt);
            }
        }
        //--------------------------------------------------------------------------------
        
    }
}
