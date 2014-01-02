using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;
using System.IO;
using System.Collections;
using Wintellect.PowerCollections;
using System.Text.RegularExpressions;
using System.Diagnostics;

namespace PCRETools
{
    class quantifier_info
    {
        public quantifier_info() { }

        public string quantifier_string = "";
        public int times_used = 0;
        public int index_in_lookup = 0;
    }

    class pcres_xml_gen
    {
        private XmlDocument doc = new XmlDocument();
        private enum property_tags
        {
            start_of_subject, // ^
            exact_string,
            negative_exact_strings,
            nested_repeatition,
            repeatition, // *, +, {}, ?
            backreference, // /x
            negative_look_ahead, // negated exact string
            group,
            or
        }

        public string FinalXml
        {
            get { return Beautify(doc); }
        }

        private Dictionary<string, quantifier_info> quantifiers = null;
        public Dictionary<string, quantifier_info> Quantifiers
        {
            get { return quantifiers; }
        }

        public string[] QuantifierStrings
        {
            get
            {
                List<string> res = new List<string>();
                foreach (string quant in quantifiers.Keys)
                    res.Add(quant);

                return res.ToArray();
            }
        }

        private UInt64[] quantifiers_lookup = new UInt64[256];
        public UInt64[] QuantifiersLookup
        {
            get { return quantifiers_lookup; }
        }

        // key - name of group
        // value - xml of group
        private Dictionary<string, XmlNode> named_groups = new Dictionary<string, XmlNode>();

        // values are xml of group
        private List<XmlNode> indexed_groups = new List<XmlNode>();        

        //--------------------------------------------------------------------------------
        public pcres_xml_gen(string xml_from_parser)
        {
            fix_xml(xml_from_parser);
            add_quantifier_groups_data();
        }
        //--------------------------------------------------------------------------------
        private void add_quantifier_groups_data()
        {
            // generate groups
            quantifiers = calculate_quantifiers();

            // build lookup and set quantifier lookup index
            build_lookup();

            // add new XML tag in PCREs that holds the lookup table
            add_lookup_table();

            // for each quantifier in the XML add an attribute that says which bit in the int64 it is.
            add_quantifiers_lookup_match_index();
        }
        //--------------------------------------------------------------------------------
        private void add_quantifiers_lookup_match_index()
        {
            XmlNodeList quantifiernodes = doc.SelectNodes("//QUANTIFIER");

            foreach (XmlNode quantifiernode in quantifiernodes)
            {
                pcre_xml pxml = new pcre_xml();

                string quantifier_group_string = pxml.parse_quantifier_group_to_string(quantifiernode);
                int index_in_lookup = this.quantifiers[quantifier_group_string].index_in_lookup;

                XmlAttribute att = doc.CreateAttribute("lookup_match_index");
                att.Value = index_in_lookup.ToString();

                quantifiernode.Attributes.Append(att);
            }
        }
        //--------------------------------------------------------------------------------
        private void add_lookup_table()
        {
            XmlNode lookup = doc.CreateElement("LOOKUP");
            
            for(int i=0 ; i<this.quantifiers_lookup.Length ; i++)
            {
                XmlNode entry = doc.CreateElement("ENTRY");

                XmlAttribute attchar = doc.CreateAttribute("char");
                XmlAttribute attmatched = doc.CreateAttribute("lookup_value");

                attchar.Value = i.ToString();
                attmatched.Value = quantifiers_lookup[i].ToString();

                entry.Attributes.Append(attchar);
                entry.Attributes.Append(attmatched);

                lookup.AppendChild(entry);
            }

            doc.FirstChild.AppendChild(lookup);

            //-------

            XmlNode quantgroups = doc.CreateElement("QUANTIFIERGROUPS");

            Dictionary<string, quantifier_info>.Enumerator it = quantifiers.GetEnumerator();
            while(it.MoveNext())
            {
                XmlNode quantifier = doc.CreateElement("QUANTIFIERGROUP");
                
                XmlAttribute attstring = doc.CreateAttribute("string");
                XmlAttribute attindex = doc.CreateAttribute("index");
                XmlAttribute atttimes = doc.CreateAttribute("times");

                attstring.Value = it.Current.Value.quantifier_string;
                attindex.Value = it.Current.Value.index_in_lookup.ToString();
                atttimes.Value = it.Current.Value.times_used.ToString();

                quantifier.Attributes.Append(attindex);
                quantifier.Attributes.Append(attstring);
                quantifier.Attributes.Append(atttimes);

                quantgroups.AppendChild(quantifier);
            }

            doc.FirstChild.AppendChild(quantgroups);
        }
        //--------------------------------------------------------------------------------
        private void build_lookup()
        {
            BitArray[] all_characters_result = new BitArray[256];
            for (int i = 0; i < 256; i++)
                all_characters_result[i] = new BitArray(64);

            string[] groups = this.QuantifierStrings;
            for (int i = 0; i < groups.Length; i++)
            {
                // get characters in group.
                Set<byte> charsInGroup = getCharsInGroup(groups[i]);

                for (int j = 0; j < all_characters_result.Length; j++)
                {
                    // if byte j exists in charsInGroup, set that group i contains byte j
                    if (charsInGroup.Contains((byte)j))
                        all_characters_result[j].Set(i, true);
                }

                quantifiers[groups[i]].index_in_lookup = i + 1; // if i==0 then bit 1 is set
            }

            // convert BitArray to UInt64
            for (int i = 0; i < 256; i++)
                quantifiers_lookup[i] = bitarrayToUint64(all_characters_result[i]);
        }
        //--------------------------------------------------------------------------------
        private Dictionary<string, quantifier_info> calculate_quantifiers()
        {
            XmlNodeList pcrexmls = doc.SelectNodes("//PCRE");

            Dictionary<string, quantifier_info> quantgroups = new Dictionary<string, quantifier_info>();
            foreach (XmlNode pcrexml in pcrexmls)
            {
                pcre_xml pxml = new pcre_xml(pcrexml);

                foreach (string quantgroup in pxml.QuantifierGroups)
                {
                    if (quantgroups.ContainsKey(quantgroup))
                        quantgroups[quantgroup].times_used++;
                    else
                    {
                        quantifier_info info = new quantifier_info();
                        info.quantifier_string = quantgroup;
                        info.times_used = 1;
                        quantgroups.Add(quantgroup, info);
                    }
                }
            }

            return quantgroups;
        }
        //--------------------------------------------------------------------------------
        private void fix_xml(string xml_from_parser)
        {
            doc.LoadXml(xml_from_parser);

            recurse_tree(doc.FirstChild);

            recurse_tree_phase_two(doc.FirstChild);

            XmlNodeList pcres = doc.FirstChild.SelectNodes("//PCRE");
            for (int i = 0; i < pcres.Count; i++)
            {
                add_tags(pcres[i], true);
            }
        }
        //--------------------------------------------------------------------------------
        private string current_ruleid = "";
        private void recurse_tree(XmlNode xmlNode)
        {
            for (int i = 0; i < xmlNode.ChildNodes.Count; i++)
            {
                try
                {

                    if (xmlNode.Name == "PCRE")
                    {
                        string ruleid = xmlNode.Attributes["ruleid"].Value;

                        if (ruleid != current_ruleid)
                        {
                            named_groups.Clear();
                            indexed_groups.Clear();
                            current_ruleid = ruleid;
                        }
                    }

                    switch (xmlNode.ChildNodes[i].Name)
                    {
                        case "LITERAL":
                            {
                                // in caes of character_class [], do not join literals
                                if (xmlNode.Name == "CHARACTER_CLASS" || xmlNode.Name == "NEGATED_CHARACTER_CLASS")
                                    continue;

                                // join literals
                                while (xmlNode.ChildNodes.Count - 1 > i && xmlNode.ChildNodes[i + 1].Name == "LITERAL")
                                {
                                    xmlNode.ChildNodes[i].Attributes["text"].InnerText += xmlNode.ChildNodes[i + 1].Attributes["text"].InnerText;
                                    xmlNode.RemoveChild(xmlNode.ChildNodes[i + 1]);
                                }

                            } break;

                        case "ALTERNATIVE":
                            {
                                XmlNode alternativenode = xmlNode.ChildNodes[i];

                                // if parent is not "OR", remove it.
                                if (alternativenode.ParentNode.Name != "OR")
                                {
                                    XmlNode parent = xmlNode;
                                    XmlNode to_remove = xmlNode.ChildNodes[i];

                                    // move all the children to be a child of their grandfather
                                    while (to_remove.HasChildNodes)
                                    {
                                        parent.InsertBefore(to_remove.ChildNodes[0], to_remove);
                                    }

                                    xmlNode.RemoveChild(to_remove);

                                    i--; // node has been removed - go back 1 of the children count
                                }
                                else
                                {
                                    // recurse the alternative node
                                    recurse_tree(xmlNode.ChildNodes[i]);
                                }

                            } break;

                        case "ANY":
                        case "WordChar":
                        case "DecimalDigit":
                        case "WhiteSpace":
                        case "CHARACTER_CLASS":
                            {
                                if (xmlNode.Name == "PCRE") // if parent is PCRE
                                {
                                    if (xmlNode.ChildNodes.Count > i && xmlNode.ChildNodes[i].HasChildNodes)
                                        recurse_tree(xmlNode.ChildNodes[i]);

                                    XmlNode characterclassnode = xmlNode.ChildNodes[i];

                                    // enclose the CHARACTER_CLASS in a quantifier where start==end==1
                                    XmlNode newquanti = doc.CreateElement("QUANTIFIER");
                                    XmlAttribute start = doc.CreateAttribute("start");
                                    start.Value = "1";
                                    XmlAttribute end = doc.CreateAttribute("end");
                                    end.Value = "1";
                                    newquanti.Attributes.Append(start);
                                    newquanti.Attributes.Append(end);

                                    newquanti.InnerXml = characterclassnode.OuterXml;
                                    xmlNode.ReplaceChild(newquanti, characterclassnode);
                                }
                                else
                                {
                                    if (xmlNode.ChildNodes.Count > i && xmlNode.ChildNodes[i].HasChildNodes)
                                        recurse_tree(xmlNode.ChildNodes[i]);
                                }
                            } break;

                        case "ELEMENT":
                            {
                                // if element and one of the children is quantifier, change element into quantifier
                                XmlNode elem = xmlNode.ChildNodes[i];
                                for (int j = 0; j < elem.ChildNodes.Count; j++)
                                {
                                    if (elem.ChildNodes[j].Name == "QUANTIFIER")
                                    {
                                        XmlNode quantnode = elem.ChildNodes[j];

                                        // create new node that replaces element node
                                        XmlNode newnode = doc.CreateElement("QUANTIFIER");
                                        XmlAttribute start = doc.CreateAttribute("start");
                                        start.Value = quantnode.ChildNodes[0].Attributes["text"].InnerText;
                                        XmlAttribute end = doc.CreateAttribute("end");
                                        end.Value = quantnode.ChildNodes[1].Attributes["text"].InnerText;
                                        newnode.Attributes.Append(start);
                                        newnode.Attributes.Append(end);

                                        // remove all quantifier node
                                        elem.RemoveChild(quantnode);

                                        // copy all the children of elem
                                        newnode.InnerXml = elem.InnerXml;

                                        // replace the nodes
                                        xmlNode.ReplaceChild(newnode, elem);
                                    }
                                    else
                                    {
                                        // recurse elem's children
                                        recurse_tree(elem);
                                    }
                                }

                            } break;

                        case "NAMED_CAPTURING_GROUP_PYTHON":
                            {
                                XmlNode capgroupnode = xmlNode.ChildNodes[i];
                                string groupName = capgroupnode.FirstChild.Attributes["text"].Value;

                                capgroupnode.RemoveChild(capgroupnode.FirstChild);

                                // create new node that replaces element node
                                XmlNode newnode = doc.CreateElement("CAPTURING_GROUP");
                                XmlAttribute name = doc.CreateAttribute("name");
                                name.Value = groupName;
                                newnode.Attributes.Append(name);

                                newnode.InnerXml = capgroupnode.InnerXml;

                                xmlNode.ReplaceChild(newnode, capgroupnode);

                                recurse_tree(newnode);

                                if (!named_groups.ContainsKey(groupName))
                                    named_groups.Add(groupName, newnode.CloneNode(true));
                                else
                                    named_groups[groupName] = newnode.CloneNode(true);
                                indexed_groups.Add(newnode.CloneNode(true));

                            } break;

                        case "CAPTURING_GROUP":
                            {
                                if (xmlNode.ChildNodes.Count > i && xmlNode.ChildNodes[i].HasChildNodes)
                                    recurse_tree(xmlNode.ChildNodes[i]);

                                indexed_groups.Add(xmlNode.ChildNodes[i].CloneNode(true));
                            } break;

                        case "RANGE":
                            {
                                XmlNode range = xmlNode.ChildNodes[i];
                                XmlAttribute start = doc.CreateAttribute("start");
                                start.Value = range.ChildNodes[0].Attributes["text"].InnerText;
                                XmlAttribute end = doc.CreateAttribute("end");
                                end.Value = range.ChildNodes[1].Attributes["text"].InnerText;
                                range.Attributes.Append(start);
                                range.Attributes.Append(end);

                                while (range.HasChildNodes)
                                    range.RemoveChild(range.FirstChild);
                            } break;

                        case "NAMED_BACKREFERENCE_PYTHON":
                            {
                                XmlNode named_backreference = xmlNode.ChildNodes[i];
                                string backreference_name = named_backreference.FirstChild.Attributes["text"].Value;

                                // replace this node with the backreference
                                xmlNode.ReplaceChild(named_groups[backreference_name].CloneNode(true), named_backreference);
                            } break;

                        case "NUMBERED_BACKREFERENCE":
                            {
                                XmlNode numbered_backreference = xmlNode.ChildNodes[i];
                                int backreference_index = int.Parse(numbered_backreference.FirstChild.Attributes["text"].Value);

                                // replace this node with the backreference
                                xmlNode.ReplaceChild(indexed_groups[backreference_index - 1].CloneNode(true), numbered_backreference);
                            } break;

                        default:
                            {
                                if (xmlNode.ChildNodes.Count > i && xmlNode.ChildNodes[i].HasChildNodes)
                                    recurse_tree(xmlNode.ChildNodes[i]);
                            } break;
                    }
                }
                catch (ArgumentOutOfRangeException ex)
                {
                    if (xmlNode.Name != "PCRE")
                        throw ex;

                    Trace.WriteLine("Removing: " + xmlNode.Attributes["ruleid"].Value);
                    Console.WriteLine("Removing: " + xmlNode.Attributes["ruleid"].Value);

                    xmlNode.ParentNode.RemoveChild(xmlNode);
                }
            }
        }
        //--------------------------------------------------------------------------------
        private void recurse_tree_phase_two(XmlNode xmlNode)
        {
            XmlNodeList capturing_groups = xmlNode.SelectNodes("PCRE/CAPTURING_GROUP");
            for(int i=0 ; i<capturing_groups.Count ; i++)
            {
                XmlNode capgroup = capturing_groups[i];

                // enclose the capturing group in a quantifier where start==end==1
                XmlNode newquanti = doc.CreateElement("QUANTIFIER");
                XmlAttribute start = doc.CreateAttribute("start");
                start.Value = "1";
                XmlAttribute end = doc.CreateAttribute("end");
                end.Value = "1";
                newquanti.Attributes.Append(start);
                newquanti.Attributes.Append(end);

                newquanti.InnerXml = capgroup.OuterXml;
                capgroup.ParentNode.ReplaceChild(newquanti, capgroup);
            }         
        }
        //--------------------------------------------------------------------------------
        private string Beautify(XmlDocument doc)
        {
            StringBuilder sb = new StringBuilder();
            XmlWriterSettings settings = new XmlWriterSettings();
            settings.Indent = true;
            settings.IndentChars = "\t";
            settings.NewLineChars = "\r\n";
            settings.Encoding = Encoding.ASCII;
            settings.NewLineHandling = NewLineHandling.Replace;
            using (XmlWriter writer = XmlWriter.Create(sb, settings))
            {
                doc.Save(writer);
            }
            string res = sb.ToString();
            return res.Remove(0, res.IndexOf("\r\n") + "\r\n".Length); // remove XML declaration
        }
        //--------------------------------------------------------------------------------
        private void add_tags(XmlNode node, bool ignore_nested = false)
        {
            XmlDocument pcredoc = new XmlDocument();
            pcredoc.LoadXml(node.OuterXml);

            List<property_tags> tags = new List<property_tags>();

            if (pcredoc.FirstChild.SelectNodes("//QUANTIFIER/*/QUANTIFIER").Count > 0)
                tags.Add(property_tags.nested_repeatition);

            if (pcredoc.FirstChild.SelectNodes("//START_OF_SUBJECT").Count > 0)
                tags.Add(property_tags.start_of_subject);

            if (pcredoc.FirstChild.SelectNodes("LITERAL").Count > 0)
                tags.Add(property_tags.exact_string);

            if (pcredoc.FirstChild.SelectNodes("NEGATIVE_LOOK_AHEAD/ELEMENT/LITERAL").Count > 0)
                tags.Add(property_tags.negative_exact_strings);

            if (pcredoc.FirstChild.SelectNodes("//QUANTIFIER").Count > 0)
                tags.Add(property_tags.repeatition);

            if (pcredoc.FirstChild.SelectNodes("//NAMED_BACKREFERENCE_PYTHON").Count > 0)
                tags.Add(property_tags.backreference);

            if (pcredoc.FirstChild.SelectNodes("//NEGATIVE_LOOK_AHEAD").Count > 0)
                tags.Add(property_tags.negative_look_ahead);

            if (pcredoc.FirstChild.SelectNodes("//CAPTURING_GROUP").Count > 0)
                tags.Add(property_tags.group);

            if (pcredoc.FirstChild.SelectNodes("//OR").Count > 0)
                tags.Add(property_tags.or);

            if (ignore_nested && tags.Contains(property_tags.nested_repeatition))
            {
                doc.FirstChild.RemoveChild(node);
                return;
            }

            string tagstext = "";
            foreach (property_tags tag in tags)
            {
                tagstext += tag.ToString() + ",";
            }

            XmlAttribute att = doc.CreateAttribute("tags");
            att.Value = tagstext;
            node.Attributes.Append(att);
        }
        //--------------------------------------------------------------------------------
        private UInt64 bitarrayToUint64(BitArray ba)
        {
            int[] ulongitem = new int[2];
            ba.CopyTo(ulongitem, 0);

            UInt64 res = 0;
            res = (UInt64)ulongitem[0];
            res |= (UInt64)ulongitem[1] << 32;

            return res;
        }
        //--------------------------------------------------------------------------------
        private Set<byte> getCharsInGroup(string group_with_stats)
        {
            string group = group_with_stats.Remove(0, group_with_stats.IndexOf(" ") + 1);

            Set<byte> res = new Set<byte>();

            // split the delimiter
            string[] group_items = group.Split(new string[] { "||" }, StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < group_items.Length; i++)
            {
                Set<byte> current_item = new Set<byte>();
                string item = group_items[i];

                item = item.Replace(@"\W", @"~\w");
                item = item.Replace(@"\S", @"~\s");
                item = item.Replace(@"\D", @"~\d");

                bool is_negated = item.StartsWith("~");

                if (is_negated)
                    item = item.Replace("~", ""); // remove ~

                if (item == "ANY")
                {
                    current_item.UnionWith(getBytes(0, 255));
                    item = item.Replace("ANY", "");
                }

                if (item.Contains(@"\s"))
                {
                    current_item.UnionWith(getBytes(new char[] { ' ', '\t', '\r', '\n' }));
                    item = item.Replace(@"\s", "");
                }

                if (item.Contains(@"\d"))
                {
                    current_item.UnionWith(getBytes('0', '9'));
                    item = item.Replace(@"\d", "");
                }

                if (item.Contains(@"\w"))
                {
                    current_item.UnionWith(getBytes('0', '9'));
                    current_item.UnionWith(getBytes('a', 'z'));
                    current_item.UnionWith(getBytes('A', 'Z'));
                    current_item.UnionWith(getBytes('_'));

                    item = item.Replace(@"\w", "");
                }

                // range \xHH-\xJJ
                if (Regex.IsMatch(item, @"\\x[0-9A-Fa-z][0-9A-Fa-z]-\\x[0-9A-Fa-z][0-9A-Fa-z]"))
                {
                    MatchCollection matches = Regex.Matches(item, @"\x[0-9A-Fa-z][0-9A-Fa-z]-\x[0-9A-Fa-z][0-9A-Fa-z]");

                    foreach (Match m in matches)
                    {
                        string[] ranges = m.Value.Replace("\\x", "").Split(new char[] { '-' });
                        current_item.UnionWith(getBytes(Convert.ToByte(ranges[0], 16), Convert.ToByte(ranges[1], 16)));

                        item = item.Replace(m.Value, "");
                    }
                }

                // \xHH to byte HH
                if (Regex.IsMatch(item, @"\\x[0-9A-Fa-z][0-9A-Fa-z]"))
                {
                    MatchCollection matches = Regex.Matches(item, @"\\x[0-9A-Fa-z][0-9A-Fa-z]");

                    foreach (Match m in matches)
                    {
                        string hexstring = m.Value.Replace("\\x", "");
                        current_item.Add(Convert.ToByte(hexstring, 16));

                        item = item.Replace(m.Value, "");
                    }
                }

                // ranges
                if (Regex.IsMatch(item, @"\w-\w"))
                {
                    MatchCollection matches = Regex.Matches(item, @"\w-\w");

                    foreach (Match m in matches)
                    {
                        string[] ranges = m.Value.Split(new char[] { '-' });
                        current_item.UnionWith(getBytes(Encoding.ASCII.GetBytes(ranges[0])[0], Encoding.ASCII.GetBytes(ranges[1])[0]));

                        item = item.Replace(m.Value, "");
                    }
                }

                // go over the string, and add all bytes
                current_item.AddMany(Encoding.ASCII.GetBytes(item));

                // if negated - get the complement values of the bytes
                if (is_negated)
                {
                    for (int b = 0; b <= 255; b++)
                    {
                        if (current_item.Contains((byte)b))
                            current_item.Remove((byte)b);
                        else
                            current_item.Add((byte)b);
                    }
                }

                res.UnionWith(current_item);
            }

            return res;
        }
        //--------------------------------------------------------------------------------
        private Set<byte> getBytes(char c)
        {
            Set<byte> res = new Set<byte>();
            res.Add(Encoding.ASCII.GetBytes(c.ToString())[0]);

            return res;
        }
        //--------------------------------------------------------------------------------
        private Set<byte> getBytes(char start, char end)
        {
            byte bstart = Encoding.ASCII.GetBytes(start.ToString())[0];
            byte bend = Encoding.ASCII.GetBytes(end.ToString())[0];

            return getBytes(bstart, bend);
        }
        //--------------------------------------------------------------------------------
        private Set<byte> getBytes(char[] items)
        {
            Set<byte> res = new Set<byte>();
            res.AddMany(Encoding.ASCII.GetBytes(items));

            return res;
        }
        //--------------------------------------------------------------------------------
        private Set<byte> getBytes(byte start, byte end)
        {
            if (end < start)
                throw new Exception("getByte arguments are invalid");

            Set<byte> res = new Set<byte>();

            for (int current = start; current <= end; current++)
                res.Add((byte)current);

            return res;
        }
        //--------------------------------------------------------------------------------
    }
}
