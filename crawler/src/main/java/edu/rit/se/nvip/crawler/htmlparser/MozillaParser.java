/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.RawVulnerability;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.ArrayList;
import java.util.List;
import java.time.LocalDate;

public class MozillaParser extends AbstractCveParser {


    /**
     * Parse advisories listed to mozilla.org/en-US/security/advisories
     * Ex: <a href="https://www.mozilla.org/en-US/security/advisories/mfsa2023-07/">...</a>
     * @param domainName - mozilla domain name
     */
    public MozillaParser(String domainName) { sourceDomainName = domainName; }

    @Override
    public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<RawVulnerability> vulnList = new ArrayList<>();

        Document doc = Jsoup.parse(sCVEContentHTML);

        Element summaryDL = doc.select("dl.summary").first();
        String date = LocalDate.now().toString();
        // extract date from the next child element after "Announced"
        if (summaryDL != null) {
            Element announced = summaryDL.children().select("dt:contains(Announced)").first();
            if (announced != null) {
                Element dateEl = announced.nextElementSibling();
                if (dateEl != null)
                    date = dateEl.text();
            }
        }

        // extract each CVE section on the page
        Elements cveSections = doc.select("section.cve");
        // add info from each section to vuln list
        for (Element cveSec : cveSections) {
            Elements children = cveSec.children();
            Element header = children.select("h4").first();
            if (header == null) continue;
            String cve = header.id();
            String description = cveSec.text();
            Element descEl = children.select("h5:contains(Description)").first();
            if (descEl != null) {
                Element descNext = descEl.nextElementSibling();
                if (descNext != null) description = descNext.text();
            }
            vulnList.add(new RawVulnerability(
               sSourceURL, cve, date, date, description, getClass().getSimpleName()
            ));
        }
        return vulnList;
    }

}
