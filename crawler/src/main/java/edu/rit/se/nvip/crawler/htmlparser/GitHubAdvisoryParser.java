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
import edu.rit.se.nvip.crawler.SeleniumDriver;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.TimeoutException;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.time.LocalDateTime;

public class GitHubAdvisoryParser extends AbstractCveParser {

    private static final Logger logger = LogManager.getLogger(RawVulnerability.class);
    public static final String DOMAIN_NAME = "github.com/advisories"; //TODO: could also be `github` need to see how this value is used

    private SeleniumDriver driver;

    /**
     * Parse advisories listed to github.com/advisories
     */
    public GitHubAdvisoryParser(SeleniumDriver driver) {
        sourceDomainName = DOMAIN_NAME;
        this.driver = driver;
    }

    /**
     * Parse advisories listed to github.com/advisories
     * @param domainName - github domain
     */
    public GitHubAdvisoryParser(String domainName, SeleniumDriver driver) { 
        sourceDomainName = domainName;
        this.driver = driver;
    }

    @Override
    public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {
        List<RawVulnerability> vulnList = new ArrayList<>();

        String html = driver.tryPageGet(sSourceURL);
        if(html == null) return vulnList;

        Document doc = Jsoup.parse(html);

        // first get CVE ID in right hand section
        Element cveIDHeader = doc.select("h3:contains(CVE ID)").first();
        String cveId = "";
        if (cveIDHeader != null)
            cveId = Objects.requireNonNull(cveIDHeader.nextElementSibling()).text();
        // if "No known CVE" or CVE section nonexistent, return empty list
        if (cveId.equals("") || cveId.contains("No known CVE")) return vulnList;

        // get description
        StringBuilder description = new StringBuilder();
        // grab p text until reaching a header. if impact header, skip
        Element descriptionElement = doc.select("div.markdown-body").first();
        if (descriptionElement != null) {
            for (Element child : descriptionElement.children()) {
                if (child.tagName().contains("h") && !child.text().contains("Impact")) break;
                else if (child.tagName().contains("h") && child.text().contains("Impact")) continue;
                description.append(child.text());
            }
        }

        // get publish and modified dates in top subhead description
        String publishDate = null;
        String lastModifiedDate = null;
        Element subhead = doc.select("div.Subhead-description").first();
        if (subhead != null) {
            Elements dates = subhead.select("relative-time");
            // non-formatted original dates found in 'title' attribute of our relative-date tags found
            if (dates.size() > 0) {
                publishDate = LocalDateTime.parse(dates.get(0).attr("datetime").substring(0,19)).toString();
                if (dates.size() > 1)
                    lastModifiedDate = LocalDateTime.parse(dates.get(1).attr("datetime").substring(0,19)).toString();
            }
        }

        if(publishDate == null){
            publishDate = LocalDateTime.now().toString();
        }
        if(lastModifiedDate == null){
            lastModifiedDate = LocalDateTime.now().toString();
        }

        vulnList.add(new RawVulnerability(
           sSourceURL, cveId, publishDate, lastModifiedDate, description.toString(), getClass().getSimpleName()
        ));

        return vulnList;
    }
}
