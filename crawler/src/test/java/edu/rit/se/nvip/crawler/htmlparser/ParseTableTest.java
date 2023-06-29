package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.crawler.CveCrawler;
import edu.rit.se.nvip.model.RawVulnerability;
import edu.rit.se.nvip.crawler.SeleniumDriver;

import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.AfterClass;
import org.junit.Ignore;

import java.util.List;
import java.util.ArrayList;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.*;

public class ParseTableTest extends AbstractParserTest {
    private static SeleniumDriver driver;

    @Test
    public void testParseTableQNAP() {
        ParseTable parser = new ParseTable("https://www.qnap.com/en/security-advisories?ref=security_advisory_details", driver);
        List<RawVulnerability> vulnerabilities = parser.parseWebPage("https://www.qnap.com/en/security-advisories?ref=security_advisory_details", null);

        assertTrue(vulnerabilities.size() > 190);
        RawVulnerability vuln = getVulnerability(vulnerabilities, "CVE-2023-22809");
        assertNotNull(vuln);
        assertEquals("2023-06-15 00:00:00", vuln.getPublishDate());
        assertTrue(vuln.getDescription().contains("A vulnerability has been reported in sudo. The vulnerability affects the following QNAP operating system"));
        assertFalse(vuln.getDescription().contains("Multiple vulnerabilities have been reported in OpenSSL. These vulnerabilities affect the following QNAP operating systems: QTS, QuTS hero, QuTScloud, QVP (QVR Pro appliances), QVR, QES"));
    }

    @Test
    public void testParseTableVMWare() {
        ParseTable parser = new ParseTable("https://www.vmware.com/security/advisories.html", driver);
        List<RawVulnerability> vulnerabilities = parser.parseWebPage("https://www.vmware.com/security/advisories.html", null);

        assertTrue(vulnerabilities.size() > 70);
        RawVulnerability vuln = getVulnerability(vulnerabilities, "CVE-2021-22035");
        assertNotNull(vuln);
        assertTrue(vuln.getPublishDate().equals("2021-10-11 00:00:00") || vuln.getPublishDate().equals("2021-10-12 00:00:00"));
        assertTrue(vuln.getDescription().contains("VMware vRealize Log Insight"));
        assertFalse(vuln.getDescription().contains("VMware Aria Operations for"));
    }

    @Test
    public void testParseTableNvidia() {
        ParseTable parser = new ParseTable("https://www.nvidia.com/en-us/security/", driver);
        List<RawVulnerability> vulnerabilities = parser.parseWebPage("https://www.nvidia.com/en-us/security/", null);

        assertTrue(vulnerabilities.size() > 400);
        RawVulnerability vuln = getVulnerability(vulnerabilities, "CVE-2017-5715");
        assertNotNull(vuln);
        assertEquals("2018-10-16 00:00:00", vuln.getPublishDate());
        assertTrue(vuln.getDescription().contains("NVIDIA SHIELD TV – October 2018"));
        assertFalse(vuln.getDescription().contains("NVIDIA Shield TV Security Updates for CPU Speculative Side Channel Vulnerabilities"));
    }

    @BeforeClass
    public static void setupWebDriver(){
        driver = new SeleniumDriver();
    }

    @AfterClass
    public static void destroyWebDriver(){
        if(driver != null) driver.tryDiverQuit();
    }
}
