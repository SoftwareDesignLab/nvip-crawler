/**
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
*/

package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.db.model.RawVulnerability;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import java.util.ArrayList;
import java.util.List;

public class LibreOfficeParser extends AbstractCveParser {

    public static final String DOMAIN_NAME = "libreoffice";

    public LibreOfficeParser() {
        sourceDomainName = DOMAIN_NAME;
    }

    /**
     * Parse advisories listed to libreoffice.org/about-us/security/advisories/
     * @param domainName - LibreOffice domain
     */
    public LibreOfficeParser(String domainName) { sourceDomainName = domainName; }

    @Override
    public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<RawVulnerability> vulnList = new ArrayList<>();
        Document doc = Jsoup.parse(sCVEContentHTML);

        // get CVE from title h3 tag
        Element cveEl = doc.select("h3:contains(CVE-)").first();
        if (cveEl == null) return vulnList; // no CVEs found, return empty list, we aren't on a CVE page
        String cve = cveEl.text();
        // get publish date from Announced:
        String publishDate = "";
        Element dateElement = doc.select("p:contains(Announced:)").first();
        if (dateElement != null)
            publishDate = getCVEDate(dateElement.text());

        // get last modified date from Updated: if it exists
        String lastModifiedDate = publishDate;
        Element updateDateElement = doc.select("p:contains(Updated:)").first();
        if (updateDateElement != null)
            lastModifiedDate = getCVEDate(updateDateElement.text());

        // get description under Description: tag
        String description = "";
        Element descriptionElement = doc.select("p:contains(Description:)").first();
        // sometimes this element is contained with the "Fixed in:" p tag and sometimes it is contained with the
        // description itself and sometimes it is in with the entire text
        // so we can just grab the entire text and split by "Description:"
        String[] descSplit = doc.text().split("Description:");
        if (descSplit.length > 1) {
            // go until Credits: or until References: or if neither exist just go until the end
            description = descSplit[1];
            String[] creditSplit = description.split("Credits:");
            String[] referenceSplit = description.split("References:");
            if (creditSplit.length > 1 || referenceSplit.length > 1) {
                if (creditSplit.length > 1) description = creditSplit[0];
                else description = referenceSplit[0];
            }
        }
        // as a fail safe take the entire article as description - these are usually short
        else
            description = doc.text();
        // add to vulns list
        vulnList.add(new RawVulnerability(sSourceURL, cve, publishDate, lastModifiedDate, description, getClass().getSimpleName()
        ));

        return vulnList;
    }
}
