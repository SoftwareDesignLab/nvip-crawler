/ **
* Copyright 2021 Rochester Institute of Technology (RIT). Developed with
* government support under contract 70RCSA22C00000008 awarded by the United
* States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the “Software”), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
* /

package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.db.model.RawVulnerability;

import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.time.LocalDate;

@Slf4j
public class ParseList extends AbstractCveParser implements ParserStrategy {

    /**
     * Generic parser list strategy
     * @param sourceDomainName - domain name of source
     */
    public ParseList(String sourceDomainName) {
        this.sourceDomainName = sourceDomainName;
    }

    @Override
    public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
        List<RawVulnerability> vulnList = new ArrayList<>();

        // Grab all of the li elements from the page
        Document doc = Jsoup.parse(sCVEContentHTML);

        //Check <li>
        Elements lists = doc.select("li:contains(CVE)");

        boolean datesNotFound = false;
        for (Element list : lists) {
            String cve;
            String desc = null;

            String listText = list.text();

            if(list.childrenSize() == 2){
                cve = getCVEID(listText);
                desc = list.child(1).text();
            }
            else{
                Element cveElement = list.select(":containsOwn(CVE)").first();
                if (cveElement == null) continue;
                cve = getCVEID(cveElement.text());
                if (cve.equals("")) continue;

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
            GenericDate genericDate = extractDate(listText);
            String publishDate = genericDate.getRawDate();
            if(publishDate == null || publishDate.equals("")){
                // logger.warn("No publish date for " + cve + ", using current date");
                datesNotFound = true;
                publishDate = LocalDate.now().toString();
            }
            GenericDate genericLastMod = extractLastModifiedDate(listText);
            String lastModifiedDate = genericLastMod.getRawDate();
            if(lastModifiedDate == null || lastModifiedDate.equals("")){
                lastModifiedDate = publishDate;
            }


            if (cve.equals("") || desc == null || desc.equals("")) continue;
            RawVulnerability vuln = new RawVulnerability(sSourceURL, cve, publishDate, lastModifiedDate, desc, getClass().getSimpleName());
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
            RawVulnerability vuln;

            String cve = null;
            String date = null;
            String lastModifiedDate = null;

            StringBuilder sb = new StringBuilder();

            for(Element child : children){
                // Once you hit a <dt> apart from the first one, create new vuln with data from prev <dd>
                if(child.tagName().equals("dt") && cve != null){
                    String desc = sb.toString();
                    if(date.equals("")){
                        // logger.warn("No publish date for " + cve + ", using current date");
                        datesNotFound = true;
                        date = LocalDate.now().toString();
                    }

                    if (!cve.equals("") && !desc.equals("")) {
                        vuln = new RawVulnerability(sSourceURL, cve, date, lastModifiedDate, desc, getClass().getSimpleName());
                        vulnList.add(vuln);
                    }

                    // Reset vars for next listing
                    cve = null;
                    date = null;
                    lastModifiedDate = null;
                    sb.delete(0, sb.length());
                }


                String dListText = child.text();

                // Check for CVE if not already grabbed
                if(cve == null || cve.equals("")){
                    cve = getCVEID(dListText);
                }

                //Check for date if not already grabbed
                if(date == null || date.equals("")){
                    GenericDate genericDate = extractDate(dListText);
                    date = genericDate.getRawDate();
                    if (date == null || date.equals("")){
                        date = LocalDate.now().toString();
                    }
                    GenericDate genericLastMod = extractLastModifiedDate(dListText);
                    lastModifiedDate = genericLastMod.getRawDate();
                    if(lastModifiedDate == null || lastModifiedDate.equals("")){
                        lastModifiedDate = date;
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
        if (datesNotFound) {
            log.warn("Some dates not found for CVEs from " + sSourceURL + ", using current date...");
        }
        return vulnList;
    }
}
