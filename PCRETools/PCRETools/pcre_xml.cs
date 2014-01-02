using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;
using Wintellect.PowerCollections;
using System.Text.RegularExpressions;

namespace PCRETools
{
    public enum property_tags
    {
        start_of_subject, // ^
        exact_string,
        negative_exact_strings,
        nested_repeatition,
        repeatition, // *, +, {}, ?
        exact_repeatition, // {}
        backreference, // /x
        negative_look_ahead, // negated exact string
        group,
        or,
    }
    //--------------------------------------------------------------------------------
    public class pcre_xml
    {
        private Set<string> quantifierGroups = new Set<string>();
        public Set<string> QuantifierGroups { get { return quantifierGroups; } }

        private Set<string> literals = new Set<string>();
        public Set<string> Literals { get { return literals; } }

        //--------------------------------------------------------------------------------
        public pcre_xml()
        {
        }
        //--------------------------------------------------------------------------------
        public pcre_xml(string xml)
        {
            parse(xml);
        }
        //--------------------------------------------------------------------------------
        public pcre_xml(XmlNode xmlnode)
        {
            parse(xmlnode.OuterXml);
        }
        //--------------------------------------------------------------------------------
        private void parse(string xml)
        {
            XmlDocument xmldoc = new XmlDocument();
            xmldoc.LoadXml(xml);

            XmlNode root = xmldoc.FirstChild;

            XmlNodeList literalNodes = root.SelectNodes("LITERAL");
            foreach (XmlNode literalNode in literalNodes)
            {
                string literaltext = literalNode.Attributes["text"].InnerText;
                MatchCollection matches = Regex.Matches(literaltext, "\\\\x([0-9a-fA-F]{2})");
                foreach(Match m in matches)
                {
                    if (m.Groups.Count > 1)
                    {
                        short charval = Convert.ToInt16(m.Groups[1].Value, 16);
                        literaltext = literaltext.Replace(m.Groups[0].Value, ((char)charval).ToString());
                    }
                }

                literals.Add(literaltext);
            }

            XmlNodeList quantifierNodes = root.SelectNodes("//QUANTIFIER");
            foreach (XmlNode quantifierNode in quantifierNodes)
            {
                string group_string = parse_quantifier_group_to_string(quantifierNode);
                quantifierGroups.Add(group_string);
            }
        }
        //--------------------------------------------------------------------------------
        public string parse_quantifier_group_to_string(XmlNode node)
        {
            Set<string> quant_group = parse_quantifier_group(node);
            string group_string = "";
            foreach (string qitem in quant_group)
                group_string += qitem;

            return group_string;
        }
        //--------------------------------------------------------------------------------
        private Set<string> parse_quantifier_group(XmlNode node)
        {
            Set<string> quantgroup = new Set<string>();

            foreach (XmlNode childquantifier in node.ChildNodes)
            {
                switch (childquantifier.Name)
                {
                    case "WhiteSpace":
                    {
                        quantgroup.Add(@"\s||");
                    } break;

                    case "NotWhiteSpace":
                    {
                        quantgroup.Add(@"~\s||");
                    } break;

                    case "LITERAL":
                    {
                        quantgroup.Add(childquantifier.Attributes["text"].Value + "||");
                    } break;

                    case "RANGE":
                    {
                        quantgroup.Add(string.Format("{0}-{1}||", childquantifier.Attributes["start"].Value, childquantifier.Attributes["end"].Value));
                    } break;

                    case "NEGATED_CHARACTER_CLASS":
                    {
                        Set<string> negated = parse_quantifier_group(childquantifier);
                        
                        foreach(string negated_string in negated)
                        {
                            quantgroup.Add("~" + negated_string);                            
                        }

                    } break;

                    case "ALTERNATIVE":
                    case "OR":
                    case "CAPTURING_GROUP":
                    case "CHARACTER_CLASS":
                    {
                        quantgroup.UnionWith(parse_quantifier_group(childquantifier));
                    } break;

                    case "ANY":
                    {
                        quantgroup.Add("ANY||");
                    } break;

                    case "WordChar":
                    {
                        quantgroup.Add(@"\w||");
                    } break;

                    case "DecimalDigit":
                    {
                        quantgroup.Add(@"\d||");
                    } break;

                    default:
                        throw new Exception("Unexpected quantifier node: " + childquantifier.Name);
                }
            }

            return quantgroup;
        }
        //--------------------------------------------------------------------------------
    }
}
