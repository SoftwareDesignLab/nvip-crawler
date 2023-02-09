package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.crawler.CveCrawler;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.IOException;
import java.net.URL;
import java.util.List;

import static org.junit.Assert.assertEquals;

/**
 * Test Parser for VMWare Security Mailing Lists
 * TODO: This source doesn't post CVEs anymore, all VMWare CVEs are now at VMWare Advisories, this should be deprecated
 */
public class VMWareParserTest {

    @Test
    public void testVMWareAdvisories() throws IOException {
        String url = "http://lists.vmware.com/pipermail/security-announce/2008/000005.html";
        String html = IOUtils.toString(new URL(url));

        MyProperties propertiesNvip = new MyProperties();
        propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);

        List<CompositeVulnerability> list = new CveCrawler(propertiesNvip).parseWebPage(url, html);

        assertEquals(5,list.size());

    }

}
