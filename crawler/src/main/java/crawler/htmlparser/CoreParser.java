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
package crawler.htmlparser;

import model.RawVulnerability;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public class CoreParser extends AbstractCveParser {

    /**
     * Parse advisories listed to coresecurity.com/core-labs/advisories
     * Ex: <a href="https://www.coresecurity.com/core-labs/advisories/pydio-cells-204-multiple-vulnerabilities">...</a>
     * @param domainName - core domain name
     */
    public CoreParser(String domainName) {
        sourceDomainName = domainName;
    }
    @Override
    public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<RawVulnerability> vulnList = new ArrayList<>();
        Document doc = Jsoup.parse(sCVEContentHTML);

        // get publish and last update date under the Advisory information section
        Elements advisoryInfo = doc.select("h2:contains(Advisory Information)");
        Element advisoryPara = advisoryInfo.first();
        String publishDate = "";
        String lastUpdatedDate = "";
        if (advisoryPara != null) {
            advisoryPara = advisoryPara.nextElementSibling();
            if (advisoryPara != null) {
                String[] pubSplit = advisoryPara.text().split("published: ");
                String[] updateSplit = advisoryPara.text().split("last update: ");
                publishDate = pubSplit[1].split(" ")[0];
                lastUpdatedDate = updateSplit[1].split(" ")[0];
            }
        }

        // get CVE IDs under Vulnerability Information section
        Element vulnInfo = doc.select("h2:contains(Vulnerability Information)").first();
        if (vulnInfo == null) return vulnList;
        Element vulnPara = vulnInfo.nextElementSibling();
        if (vulnPara == null) return vulnList;
        // usually separated by , or ;
        Set<String> cves = getCVEs(vulnPara.text());

        // get Vulnerability Description for every CVE on page
        StringBuilder vulnDesc = new StringBuilder();
        Element descTitle = doc.select("h2:contains(Vulnerability Description)").first();
        if (descTitle != null) {
            Element next = descTitle.nextElementSibling();
            while (next != null && !next.tagName().contains("h")) {
                vulnDesc.append(next.text());
                next = next.nextElementSibling();
            }
        }
        // get Technical Description foreach CVE on the page, combine with main Vulnerability Description
        // Note: good chance these technical descriptions are out of order found in cves list
        Elements techDescs = doc.select("h2:contains(7.), h3:contains(7.)");
        // remove the main 7.Technical Description header from the list
        techDescs.remove(0);
        if (techDescs.size() != 0) {
            for (Element techDescTitle : techDescs) {
                Element nextTech = techDescTitle.nextElementSibling();
                if (nextTech == null) continue;
                String desc = nextTech.text();
                // if multiple, these might have [ CVE ]
                if (desc.contains("[CVE-")) {
                    // connect this to one of our above CVEs and add to vuln list
                    Iterator<String> iter = cves.iterator();
                    while(iter.hasNext()) {
                        String c = iter.next();
                        if (desc.contains(c)) {
                            desc = desc.split(c+"]")[1];
                            vulnList.add(new RawVulnerability(
                               0, sSourceURL, c, null, publishDate, lastUpdatedDate, vulnDesc + desc, sourceDomainName
                            ));
                            iter.remove();
                        }
                    }
                }
                // if single, these might not have [ ]
                else {
                    // outlier: CVE alone on a line under it
                    // source: https://www.coresecurity.com/core-labs/advisories/viper-rgb-driver-multiple-vulnerabilities
                    // if it goes right into proof of concept code or talks about versions not patched, skip for now...
                    // otherwise, this looks to be just a single CVE, just attach this desc to main vulndesc
                    if (!desc.contains("the following exploit:") && !desc.contains("Below")) {
                        vulnDesc.append(desc);
                    }
                }
            }
        }
        if (cves.size() != 0) {
            for (String c : cves) {
                vulnList.add(new RawVulnerability(
                        0, sSourceURL, c, null, publishDate, lastUpdatedDate, vulnDesc.toString(), sourceDomainName
                ));
                cves.remove(c);
            }
        }

        return vulnList;
    }
}
