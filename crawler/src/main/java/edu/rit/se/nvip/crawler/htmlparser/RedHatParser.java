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
import lombok.extern.slf4j.Slf4j;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Web Parser for RedHat CVE Page
 * (ex. https://access.redhat.com/security/cve/cve-2023-25725)
 */
@Slf4j
public class RedHatParser extends AbstractCveParser {

    public static final String DOMAIN_NAME = "redhat";

    public RedHatParser() {
        sourceDomainName = DOMAIN_NAME;
    }

    public RedHatParser(String domainName) {
		sourceDomainName = domainName;
	}

    @Override
	public List<RawVulnerability> parseWebPage(String sSourceURL, String sCVEContentHTML) {

        List<RawVulnerability> vulnerabilities = new ArrayList<>();

        try {
            Document doc = Jsoup.parse(sCVEContentHTML);

            String cve = doc.select("h1.headline").text();
            String description = doc.select("#cve-details-description > div > div > pfe-markdown > p").text();

            String publishedDate = doc.select("p.cve-public-date > pfe-datetime").attr("datetime");
            String modifiedTimestamp = doc.select("p.cve-last-modified > pfe-datetime").attr("timestamp");

            String lastModifiedDate = LocalDateTime.ofEpochSecond(Integer.parseInt(modifiedTimestamp), 0, ZoneOffset.UTC).toString();
            DateTimeFormatter publishFormatter = DateTimeFormatter.ISO_OFFSET_DATE_TIME;
            LocalDateTime date = LocalDateTime.parse(publishedDate, publishFormatter);
            publishedDate = date.toString();

            vulnerabilities.add(new RawVulnerability(sSourceURL, cve, publishedDate, lastModifiedDate, description, getClass().getSimpleName()));
        } catch (Exception e) {
            log.error("Error parsing {}: {}", sSourceURL, e.toString());
        }
        return vulnerabilities;
	}

}