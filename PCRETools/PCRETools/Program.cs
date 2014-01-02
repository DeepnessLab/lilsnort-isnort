using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using Wintellect.PowerCollections;
using System.Xml;
using System.Collections;

namespace PCRETools
{
    class Program
    {
        //--------------------------------------------------------------------------------
        static void Main(string[] args)
        {
            // set current directory to the root of "Network Workshop" directory.
            Environment.CurrentDirectory = Environment.CurrentDirectory + @"..\..\..\..\..\";

            string name = "20_cqc_pcres";
            
            pcres_xml_gen xml_gen = new pcres_xml_gen(File.ReadAllText(".\\rules\\" + name + "_raw.xml"));
            string final_xml = xml_gen.FinalXml;
            File.WriteAllText(".\\rules\\" + name + ".xml", final_xml);
            
            //File.WriteAllBytes(".\\inputs\\" + name + "_content_attack_packet.txt", attack_packet.forge_attack_packet(".\\rules\\" + name + ".rules"));
            //File.WriteAllBytes(".\\inputs\\" + name + "_full_attack_packet.txt", attack_packet.forge_advanced_attack_packet(".\\rules\\" + name + ".rules", ".\\rules\\" + name + ".xml"));
                        
        }
        //--------------------------------------------------------------------------------
                
    }
}
