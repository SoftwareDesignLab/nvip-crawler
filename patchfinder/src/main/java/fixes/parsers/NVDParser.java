package fixes.parsers;

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

import fixes.Fix;
import fixes.FixFinderThread;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 * HTML parser for NVD web pages
 *
 * @author Paul Vickers
 * @author Dylan Mulligan
 */
public class NVDParser extends FixParser {
    // Enumeration of desired tags related to collected resources from NVD pages (direct sources)
    private enum RESOURCE_TAGS {
        PATCH("Patch"), // Hyperlink relates directly to patch information
        VENDOR_ADVISORY("Vendor Advisory"), // Hyperlink relates to an advisory host
        THIRD_PARTY_ADVISORY("Third Party Advisory"), // Hyperlink relates to a third-party advisory host
        EXPLOIT("Exploit"), // Hyperlink relates to exploit information
        ISSUE_TRACKING("Issue Tracking"); // Hyperlink relates to an issue tracking host

        private final String name;
        RESOURCE_TAGS(String name) {
            this.name = name;
        }

        /**
         * Safe valueOf method that relates tag name (i.e. "Vendor Advisory") to the correct member
         * @param name name of resource tag
         * @return correlated tag object, or null if not found
         */
        public static RESOURCE_TAGS fromString(String name) {
            for(RESOURCE_TAGS tag : RESOURCE_TAGS.values()) {
                if(tag.name.equalsIgnoreCase(name)) return tag;
            }
            return null;
        }
    }

    protected NVDParser(String cveId, String url){
        super(cveId, url);
    }

    /**
     * Method used to parse an NVD CVE vulnerability webpage for fixes. Main functionality is to
     * scrape for the references table and then delegate to other parsers for those sources.
     *
     * @return List of fixes for the CVE
     * @throws IOException if an error occurs during scraping
     */
    @Override
    public List<Fix> parseWebPage() throws IOException{
        // Isolate the HTML for the references table
        Elements rows = this.DOM.select("div[id=vulnHyperlinksPanel]").first().select("table").first().select("tbody").select("tr");

        // For each URL stored in the table, if it has a "Patch" badge associated with it, add it to fixSources
        List<String> fixSources = new ArrayList<>();
        for(Element row : rows){
            String url = row.select("a").text();
            Elements spans = row.select("span.badge");
            // Check all resource tags
            for(Element span: spans){
                // Add url if the tag matches any whitelisted tag
                if(RESOURCE_TAGS.fromString(span.text()) != null) fixSources.add(url);
            }
        }

        // For each URL, find the correct parser for it and add the fixes found for that URL
        for(String fixSource : fixSources){
            FixParser parser = FixParser.getParser(cveId, fixSource);
            this.fixes.addAll(parser.parse());
        }

        return this.fixes;
    }
}
