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

        CveCrawlController controller = new CveCrawlController();
        HashMap<String, Object> vars = new HashMap<>();
        vars.put("outputDir", "output/crawlers");
        vars.put("crawlerPoliteness", 3000);
        vars.put("maxPages", -1);
        vars.put("depth", 1);
        vars.put("enableReport", false);
        vars.put("crawlerNum", 1);
        HashMap<String, ArrayList<RawVulnerability>> map = controller.crawl(urls, whiteList, vars);

        assertTrue(map.size() > 0);
    }

}
