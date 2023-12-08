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
import java.util.Arrays;
import java.util.List;

public class SambaParser extends AbstractCveParser {

    public static final String DOMAIN_NAME = "samba.org";

    public SambaParser() {
        sourceDomainName = DOMAIN_NAME;
    }

    /**
     * Parse advisories in announcements column
     * listed to samba.org/samba/history/security.html
     * @param domainName - Samba domain
     */
    public SambaParser(String domainName) { sourceDomainName = domainName; }

    @Override
    public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        // ignore links to patch files
        if (sSourceURL.contains(".patch")) return null;

        // otherwise parse a page linked under "Announcements"
        List<RawVulnerability> vulnList = new ArrayList<>();
        Document doc = Jsoup.parse(sCVEContentHTML);

        // each page has a title h2 with the rest being text
        Element titleEl = doc.select("h2").first();
        if (titleEl == null) return vulnList; // no CVEs found, return empty list, we aren't on a CVE page
        String cve = getCVEID(titleEl.text());

        Element textEl = doc.select("pre").first();
        if (textEl == null) return vulnList;
        String pageText = textEl.text();
        pageText = pageText.replace("\r", "");

        // grab description between ===Description=== and ===Patch Availability===
        StringBuilder description = new StringBuilder();
        String[] lines = pageText.split("\n");
        // get idx of Description and + 1 to skip the ======= after it...
        // go until we reach another =======
        int descIdx = Arrays.asList(lines).indexOf("Description");
        for (int i = descIdx + 2; i < lines.length; i++) {
            if (lines[i].startsWith("======")) break;
            description.append(lines[i]).append(" ");
        }

        // dates are not found on these individual pages, only the root
        // we would need a way to grab those too

        // for now just add to list
        vulnList.add(new RawVulnerability(sSourceURL, cve, "", "", description.toString(), getClass().getSimpleName()
        ));

        return vulnList;
    }
}
