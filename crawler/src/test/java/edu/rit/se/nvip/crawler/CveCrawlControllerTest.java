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

package edu.rit.se.nvip.crawler;

import edu.rit.se.nvip.db.model.RawVulnerability;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;


public class CveCrawlControllerTest {

    @Disabled("Integration test that needs to be refactored: Should not crawl the web!")
    @Test
    public void CveCrawlControllerTest() throws Exception {
        List<String> urls = new ArrayList<>();
        urls.add("https://www.jenkins.io/security/advisory/2023-03-21/");

        List<String> whiteList = new ArrayList<>();
        whiteList.add("https://www.jenkins.io/security/advisory");

        HashMap<String, Object> vars = new HashMap<>();
        vars.put("outputDir", "output/crawlers");
        vars.put("crawlerPoliteness", 3000);
        vars.put("maxPages", -1);
        vars.put("depth", 1);
        vars.put("enableReport", false);
        vars.put("crawlerNum", 1);

        CveCrawlController controller = new CveCrawlController(urls, whiteList, vars);
        HashMap<String, ArrayList<RawVulnerability>> map = controller.crawl();

        assertTrue(map.size() > 0);
    }

}
