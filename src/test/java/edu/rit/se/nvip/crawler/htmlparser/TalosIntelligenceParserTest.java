package edu.rit.se.nvip.crawler.htmlparser;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

import edu.rit.se.nvip.crawler.CveCrawler;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.Vulnerability;
import edu.rit.se.nvip.utils.MyProperties;
import edu.rit.se.nvip.utils.PropertyLoader;
import edu.rit.se.nvip.utils.UtilHelper;

public class TalosIntelligenceParserTest {

	@Test
	public void testTalosIntelligence() throws IOException {

		MyProperties propertiesNvip = new MyProperties();
		propertiesNvip = new PropertyLoader().loadConfigFile(propertiesNvip);
		
		CveCrawler crawler = new CveCrawler(propertiesNvip);
		String html = FileUtils.readFileToString(new File("src/test/resources/test-talos.html"));
		List<CompositeVulnerability> list = crawler.parseWebPage("talosintelligence", html);
		assertEquals(true, list.size()>0);
	}

}
