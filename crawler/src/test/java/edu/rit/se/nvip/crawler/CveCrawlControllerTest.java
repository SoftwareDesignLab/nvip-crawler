package edu.rit.se.nvip.crawler;

import edu.rit.se.nvip.model.RawVulnerability;
import org.junit.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import static org.junit.Assert.assertTrue;

public class CveCrawlControllerTest {

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
