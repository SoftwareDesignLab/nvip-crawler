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
import java.time.LocalDate;

public class ParseList extends AbstractCveParser implements ParserStrategy {

    private final Logger logger = LogManager.getLogger(getClass().getSimpleName());

    /**
     * Generic parser list strategy
     * @param sourceDomainName - domain name of source
     */
    public ParseList(String sourceDomainName) {
        this.sourceDomainName = sourceDomainName;
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

            String listText = list.text();

            if(list.childrenSize() == 2){
                cve = getCVEID(listText);
                desc = list.child(1).text();
            }
            else{
                Element cveElement = list.select(":containsOwn(CVE)").first();
                cve = getCVEID(cveElement.text());

                // First check the next sibling element if its CVE related If so, its prolly the desc
                Element descElement = cveElement.nextElementSibling();
                if(descElement != null){
                    Pattern cvePattern = Pattern.compile(regexAllCVERelatedContent);
                    Matcher cveMatcher = cvePattern.matcher(descElement.text());

                    if (!cveMatcher.find()){
                        // Next element after the CVE ID is not the desc, see if 
                        // theres someting that defines detail/descrption/summery
                        descElement = list.select(":containsOwn(detail), :containsOwn(description)").first();

                        if(descElement == null){
                            // If theres no detail/description/summary, grab first <p> that has CVE related content
                            descElement = list.select("p:matchesOwn(" + regexAllCVERelatedContent + ")").first();
                        }
                    }
                    // All else fails, grab the inner text of the <li>
                    if (descElement == null)
                        desc = list.ownText();
                    else
                        desc = descElement.text();
                }
            }
            GenericDate genericDate = new GenericDate(listText);
            date = genericDate.getRawDate();
            if(date == null || date.equals("")){
                logger.warn("No publish date for " + cve + ", using current date");
                date = LocalDate.now().toString();
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
        Elements dLists = doc.select("dl:contains(CVE)");

        for(Element dList : dLists){
            Elements children = dList.children();
            CompositeVulnerability vuln = null;

            String cve = null;
            String date = null;

            StringBuilder sb = new StringBuilder();

            for(Element child : children){
                // Once you hit a <dt> apart from the first one, create new vuln with data from prev <dd>
                if(child.tagName() == "dt" && cve != null){
                    String desc = sb.toString();
                    if(date == "" || date == null){
                        logger.warn("No publish date for " + cve + ", using current date");
                        date = LocalDate.now().toString();
                    }

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


                String dListText = child.text();

                // Check for CVE if not already grabbed
                if(cve == null || cve == ""){
                    cve = getCVEID(dListText);
                }

                //Check for date if not already grabbed
                if(date == null || date.equals("")){
                    GenericDate genericDate = new GenericDate(dListText);
                    date = genericDate.getRawDate();
                    if (date == null || date.equals("")){
                        date = LocalDate.now().toString();
                    }
                }

                // Grab description to append (desc might be in multiple <dd>)
                Element descElement = child.select(":matchesOwn(" + regexAllCVERelatedContent + ")").first();

                if(descElement != null){
                    // Make sure it isn't the CVE ID
                    Pattern cvePattern = Pattern.compile(regexCVEID);
                    Matcher cveMatcher = cvePattern.matcher(descElement.text());
                    if (!cveMatcher.find()) {
                        sb.append(descElement.text());
                        sb.append(" ");
                    }
                }
            }

        }
        return vulnList;
    }
}
