/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RCSA22C00000008 awarded by the United
 * States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

public class ArubaParser extends AbstractCveParser {

    public static final String DOMAIN_NAME = "arubanetworks";

    public ArubaParser() {
        sourceDomainName = DOMAIN_NAME;
    }

    /**
     * Parse text listed to Aruba bulletin arubanetworks.com/support-services/security-bulletins/
     * @param domainName - arubanetworks domain
     */
    public ArubaParser(String domainName) { sourceDomainName = domainName; }

    /**
     * Get text under a certain === header
     * @param sections - text split by === (thus a header title is a part of the previous split)
     * @return - section text under a title
     */
    private String getSection(List<String> sections, String title) {
        String sectionText = "";
        for (int i = 0 ; i < sections.size() ; i++ ) {
            String section = sections.get(i).replace("\r", "");
            if (section.contains("\n" + title + "\n")) {
                String nextSection = sections.get(i + 1);
                String[] nextSections = nextSection.split("\n\n");
                for (int j = 1; j < nextSections.length; j++){
                    sectionText = sectionText + nextSections[j];
                }
            }
        }
        return sectionText;
    }

    /**
     * Get details text under a certain CVE header
     * @param detailsSections - list of split details sections by ---------
     * @param cve - given cve to return details for
     * @return - string containing that CVEs details section
     */
    protected String splitDetailsSection(List<String> detailsSections, String cve) {
        String thisCveDetails = "";
        for (int i = 0 ; i < detailsSections.size() ; i++) {
            String thisDetailHeader = detailsSections.get(i);
            if (thisDetailHeader.contains(cve)) {
                String detailText = detailsSections.get(i + 1).replace("\r", "");
                detailText = detailText.split("\n\n\n")[0];
                thisCveDetails = detailText;
            }
        }

        return thisCveDetails;
    }

    /**
     * Get rid of empty strings from line split,
     * return a list containing no empty strings,
     * in the same order
     */
    protected List<String> omitEmptyStrings(String[] split) {
        List<String> sections = new ArrayList<>(Arrays.asList(split));
        sections.removeAll(Arrays.asList("", null));
        return sections;
    }

    @Override
    public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<RawVulnerability> vulnList = new ArrayList<>();

        Document doc = Jsoup.parse(sCVEContentHTML);

        String docText = doc.text();

        // get CVE IDs
        Set<String> cves = getCVEs(sCVEContentHTML);

        // get publication date from the top
        String publishDate = "";
        String[] sectionSplit = docText.split("===");
        List<String> sections = omitEmptyStrings(sectionSplit);
        String topCategorySplit = sections.get(1);
        if (topCategorySplit.contains("Publication Date")) {
            String dateSplit = topCategorySplit.split("Publication Date: ")[1];
            publishDate = dateSplit
                    .replace("\n", " ")
                    .replace("\r", "")
                    .split(" ")[0]
                    .trim();
        }

        // get last updated from top, if not there, use publication date
        String lastUpdated = publishDate;
        if (topCategorySplit.contains("Last Update")) {
            String updateSplit = topCategorySplit.split("Last Update: ")[1];
            lastUpdated = updateSplit
                    .replace("\n", " ")
                    .replace("\r", "")
                    .split(" ")[0]
                    .trim();
        }

        // get description by combining 'Overview' and 'Details' sections
        String description = "";
        String overviewSection = getSection(sections, "Overview");
        overviewSection = overviewSection.replace("Affected Products", "");
        // if multiple CVEs, details section is going to have descriptions foreach CVE
        String detailsSection = getSection(sections, "Details");

        if (cves.size() > 1) {
            for (String cve : cves) {
                String[] detailsSections = detailsSection.split("---------");
                description = overviewSection + splitDetailsSection(omitEmptyStrings(detailsSections), cve);
                vulnList.add(new RawVulnerability(
                        sSourceURL, cve, publishDate, lastUpdated, description, getClass().getSimpleName()
                ));
            }
        }
        else {
            description = overviewSection + detailsSection;
            ArrayList<String> cveList = new ArrayList<>(cves);
            vulnList.add(new RawVulnerability(
                    sSourceURL, cveList.get(0), publishDate, lastUpdated, description, getClass().getSimpleName()
            ));
        }

        return vulnList;
    }
}
