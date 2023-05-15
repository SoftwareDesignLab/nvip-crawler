package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ParseList extends AbstractCveParser implements ParserStrategy {

    private final Logger logger = LogManager.getLogger(getClass().getSimpleName());

    private String grabDate(String sourceHtml){
        String date = getCVEDate(sourceHtml);
        if(date == ""){
            Pattern dayMonthYearPattern = Pattern.compile("([1-9]|[12]\\d|3[01])\\s"
                + "(Jan(uary)?|Feb(ruary)?|Mar(ch)?|Apr(il)?|May|Jun(e)?|Jul(y)?|Aug(ust)?|Sep(tember)?|Oct(ober)?|Nov(ember)?|Dec(ember)?)"
                + "\\s([12]\\d{3})");
            Matcher dateMatcher = dayMonthYearPattern.matcher(sourceHtml);
            if(dateMatcher.find())
                date = dateMatcher.group();
        }
        return date;
    }

    @Override
    public List<CompositeVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
        List<CompositeVulnerability> vulnList = new ArrayList<>();

        // Grab all of the li elements from the page
        Document doc = Jsoup.parse(sCVEContentHTML);

        //Check <li>
        Elements lists = doc.select("li:contains(CVE)");

        for (Element list : lists) {
            String cve = null;
            String date = null;
            String desc = null;

            if(list.childrenSize() == 2){
                String list_txt = list.text();
                cve = getCVEID(list_txt);
                date = grabDate(list_txt);
                desc = list.child(1).text();
            }
            else{
                Element cve_el = list.select(":containsOwn(CVE)").first();
                cve = getCVEID(cve_el.text());

                // First check the next sibling element if its CVE related If so, its prolly the desc
                Element desc_el = cve_el.nextElementSibling();
                if(desc_el != null){
                    Pattern cvePattern = Pattern.compile(regexAllCVERelatedContent);
                    Matcher cveMatcher = cvePattern.matcher(desc_el.text());

                    if (!cveMatcher.find()){
                        // Next element after the CVE ID is not the desc, see if 
                        // theres someting that defines detail/descrption/summery
                        desc_el = list.select(":containsOwn(detail), :containsOwn(description)").first();

                        if(desc_el == null){
                            // If theres no detail/description/summary, grab first <p> that has CVE related content
                            desc_el = list.select("p:matchesOwn(" + regexAllCVERelatedContent + ")").first();
                        }
                    }
                    // All else fails, grab the inner text of the <li>
                    if (desc_el == null)
                        desc = list.ownText();
                    else
                        desc = desc_el.text();

                    date = grabDate(list.text());
                    if(date == ""){
                        logger.warn("No publish date for " + cve);
                    }
                }
            }

            CompositeVulnerability vuln = new CompositeVulnerability(0, sSourceURL, cve, null, date, null, desc, sourceDomainName);
            // logger.info(vuln.getCveId());
            // logger.info(vuln.getDescription());
            // logger.info(vuln.getPublishDate() + "\n");
            vulnList.add(vuln);
        }

        // Grab all <dl> elements
        // From what I can see it follows the format of
        // <dl>
        //      <dt>
        //      <dd>
        //      <dd>
        //      ...
        //      <dt>
        //      <dd>
        //      <dd>
        //      ...
        // </dl>
        Elements dlists = doc.select("dl:contains(CVE)");

        for(Element dlist : dlists){
            Elements children = dlist.children();
            CompositeVulnerability vuln = null;

            String cve = null;
            String date = null;

            StringBuilder sb = new StringBuilder();

            for(Element child : children){
                // Once you hit a <dt> apart from the first one, create new vuln with data from prev <dd>
                if(child.tagName() == "dt" && cve != null){
                    String desc = sb.toString();
                    vuln = new CompositeVulnerability(0, sSourceURL, cve, null, date, null, desc, sourceDomainName);
                    // logger.info(vuln.getCveId());
                    // logger.info(vuln.getDescription());
                    // logger.info(vuln.getPublishDate() + "\n");
                    vulnList.add(vuln);

                    // Reset vars for next listing
                    cve = null;
                    date = null;
                    sb.delete(0, sb.length());
                }


                String dlist_txt = child.text();

                // Check for CVE if not already grabbed
                if(cve == null || cve == ""){
                    cve = getCVEID(dlist_txt);
                }

                //Check for date if not already grabbed
                if(date == null || date == ""){
                    date = grabDate(dlist_txt);
                }

                // Grab description to append (desc might be in multiple <dd>)
                Element desc_el = child.select(":matchesOwn(" + regexAllCVERelatedContent + ")").first();

                if(desc_el != null){
                    // Make sure it isn't the CVE ID
                    Pattern cvePattern = Pattern.compile(regexCVEID);
                    Matcher cveMatcher = cvePattern.matcher(desc_el.text());
                    if (!cveMatcher.find())
                        sb.append(desc_el.text());
                        sb.append(" ");
                }
            }

        }
        return vulnList;
    }
}
