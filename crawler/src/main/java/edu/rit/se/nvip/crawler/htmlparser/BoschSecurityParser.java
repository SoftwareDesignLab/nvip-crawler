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

import edu.rit.se.nvip.db.model.RawVulnerability;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.ArrayList;
import java.util.List;

/**
 * Web Parser for Bosch Security Advisory Boards
 */
public class BoschSecurityParser extends AbstractCveParser {

    public static final String DOMAIN_NAME = "bosch";

    public BoschSecurityParser() {
        sourceDomainName = DOMAIN_NAME;
    }

    public BoschSecurityParser(String domainName) {
        sourceDomainName = domainName;
    }

    /**
     * Parse Bosch Security Advisory
     * (ex. https://psirt.bosch.com/security-advisories/bosch-sa-247053-bt.html)
     * (ex. https://psirt.bosch.com/security-advisories/bosch-sa-464066-bt.html)
     * TODO: Grab CWEs for each CVE
     * @param sSourceURL
     * @param sCVEContentHTML
     * @return
     */
    @Override
    public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<RawVulnerability> vulns = new ArrayList<>();

        Document doc = Jsoup.parse(sCVEContentHTML);
        try {
            Element advisoryInformation = doc.getElementById("advisory-information");
            if (advisoryInformation == null) return vulns;
            advisoryInformation = advisoryInformation.nextElementSibling();
            if (advisoryInformation == null) return vulns;
            Elements dates = advisoryInformation.children();

            String publishDate = dates.get(2).children().get(1).text().substring(10).trim();
            String updateDate = dates.get(3).children().get(1).text().substring(13).trim();

            Elements headers = doc.getElementsByTag("h3");
            for (Element header : headers) {
                if (header.id().contains("cve-") && !header.id().contains("cvss")) {
                    String cveId = header.id().toUpperCase();
                    Element next = header.nextElementSibling();
                    if (next != null) {
                        String description = next.text().substring(17);
                        vulns.add(new RawVulnerability(sSourceURL, cveId, publishDate, updateDate, description, getClass().getSimpleName()));
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return vulns;
    }
}
