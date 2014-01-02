import org.antlr.runtime.tree.CommonTree;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import pcreparser.PCRE;
import pcreparser.PCREParser;

import javax.xml.parsers.*;
import org.w3c.dom.*;
import java.io.*;
import java.util.*;


public class mainclass
{
    public static void main(String[] args)
    {
        String name = "20_cqc_pcres";

        String rulesfilename = "..\\rules\\"+name+".rules";

        try
        {
            // load rules.
            File frules = new File(rulesfilename);
            FileReader fr = new FileReader(rulesfilename);
            BufferedReader br = new BufferedReader(fr);

            ArrayList<String[]> pcres = new ArrayList<String[]>();

            while (br.ready())
            {
                String[] pcreAndRule = parsePCRE(br.readLine());

                if(pcreAndRule != null)
                    pcres.add(pcreAndRule);
            }

            System.out.println("Loaded "+pcres.size()+" PCREs");

            String res = "<PCRES>\r\n";
            for(int i=0 ; i<pcres.size() ; i++)
            {
                PCRE pcre = new PCRE(pcres.get(i)[0]);
                res += toXML(pcre, pcres.get(i)[1], 1, pcres.get(i)[0]);
            }
            res += "</PCRES>";

            BufferedWriter bw = new BufferedWriter(new FileWriter("..\\rules\\"+name+"_raw.xml"));

            bw.write(res, 0, res.length());
            bw.flush();
            bw.close();
        }
        catch (Exception e)
        {
            System.out.println(e.getMessage());
            e.printStackTrace();
        }
    }

    private static String toXML(PCRE pcre, String ruleid, int indent_count, String PCREtext)
    {
        StringBuilder resbuilder = new StringBuilder();
        StringBuilder xmlbuilder = new StringBuilder();

        String indent = "";
        for (int i = 0; i < indent_count; i++)
            indent += "\t";

        boolean isPCRECommentEscape = false;
        if(PCREtext.contains("--"))
        {
            PCREtext = PCREtext.replaceAll("--", "- -");
            isPCRECommentEscape = true;
        }

        resbuilder.append(indent).append("<PCRE ruleid='").append(ruleid).append("'>").append("\t<!-- ").append(PCREtext)
                .append(isPCRECommentEscape ? "\tPCRE - has been escaped" : "")
                .append(" -->")
                .append("\r\n");
        recursive_walk(pcre.getCommonTree(0), xmlbuilder, indent_count + 1);
        resbuilder.append(xmlbuilder.toString());
        resbuilder.append(indent).append("</PCRE>").append("\r\n");

        return resbuilder.toString();
    }

    private static String get_name(CommonTree tree)
    {
        return PCREParser.tokenNames[tree.getType()];
    }

    private static String get_text(CommonTree tree)
    {
        String text = tree.getText().equals(get_name(tree)) ? "" : tree.getText();
        text = text.equals("2147483647") ? "INF" : text;
        return text;
    }

    private static void recursive_walk(CommonTree tree, StringBuilder builder, int indent_count)
    {
        String name = get_name(tree);
        String text = get_text(tree);

        boolean is_ignore_trace =/* name.equals("ALTERNATIVE") ||*/
                                 (name.equals("ELEMENT") && tree.getChildCount() < 2);

        if(!is_ignore_trace)
            trace_before(name, text, tree, builder, indent_count);

        if(tree.getChildCount() > 0)
        {
            for(int i=0 ; i<tree.getChildCount() ; i++)
                recursive_walk((CommonTree)tree.getChild(i), builder, !is_ignore_trace ? indent_count+1 : indent_count);

            if(!is_ignore_trace)
                trace_after(name, tree, builder, indent_count);
        }
    }

    private static void trace_before(String name, String text, CommonTree tree, StringBuilder builder, int indent_count)
    {

        String indent = "";
        for (int i = 0; i < indent_count; i++)
            indent += "\t";

        builder.append(indent)
                .append("<").append(name)
                .append(text.isEmpty() ? "" : " text='"+encodeXML(text)+"'")
                .append(tree.getChildCount() == 0 ? " />" : ">")
                .append("\r\n");
    }

    private static void trace_after(String name, CommonTree tree, StringBuilder builder, int indent_count)
    {
        String indent = "";
        for (int i = 0; i < indent_count; i++)
            indent += "\t";

        builder.append(indent)
                .append("</").append(name).append(">")
                .append("\r\n");
    }

    private static String[] parsePCRE(String rule)
    {
        if (rule.startsWith("#")) // comment - ignore this rule
            return null;

        if (!rule.contains("pcre:\"/"))
            return null;

        String[] res = new String[2];

        int pcreStart = rule.indexOf("pcre:\"/") + "pcre:\"/".length();
        int pcreEnd = rule.indexOf("\"; ", pcreStart);

        String pcreWithOptions = rule.substring(pcreStart, pcreEnd);
        res[0] = pcreWithOptions.substring(0, pcreWithOptions.lastIndexOf("/"));

        int ruleidStart = rule.indexOf("sid:") + "sid:".length();
        int ruleidEnd = rule.indexOf(";", ruleidStart);

        res[1] = rule.substring(ruleidStart, ruleidEnd);

        return res;
    }

     private static String encodeXML(String text)
    {
        text = text.replaceAll("&", "&amp;");
        text = text.replaceAll("\"", "&quot;");
        text = text.replaceAll("'", "&apos;");
        text = text.replaceAll("<", "&lt;");
        text = text.replaceAll(">", "&gt;");
        text = text.replaceAll("\0", "\\\\x00");

        text = text.replaceAll(String.valueOf((char)0x4), "\\\\x04");
        text = text.replaceAll(String.valueOf((char)0xC), "\\\\x0C");
        text = text.replaceAll(String.valueOf((char)0x1), "\\\\x01");
        text = text.replaceAll(String.valueOf((char)0x7), "\\\\x07");
        text = text.replaceAll(String.valueOf((char)0x8), "\\\\x08");
        text = text.replaceAll(String.valueOf((char)0x6), "\\\\x06");
        text = text.replaceAll(String.valueOf((char)0x0A), "\\\\x0A");
        text = text.replaceAll(String.valueOf((char)0x0D), "\\\\x0D");
        text = text.replaceAll(String.valueOf((char)0x10), "\\\\x10");
        text = text.replaceAll(String.valueOf((char)0x13), "\\\\x13");
        text = text.replaceAll(String.valueOf((char)0xFF), "\\\\xFF");
        text = text.replaceAll(String.valueOf((char)0x2F), "\\\\x2F");
        text = text.replaceAll(String.valueOf((char)0xce), "\\\\xCE");
        text = text.replaceAll(String.valueOf((char)0xec), "\\\\xEC");
        text = text.replaceAll(String.valueOf((char)0xed), "\\\\xED");
        text = text.replaceAll(String.valueOf((char)0xf4), "\\\\xF4");

        return text;
    }
}
