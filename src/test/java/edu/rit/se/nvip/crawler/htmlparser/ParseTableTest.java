package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.crawler.CveCrawler;
import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;
import java.util.List;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.*;

public class ParseTableTest extends AbstractParserTest {

    @Test
    public void testParseTableQNAP() {
        ParseTable parser = new ParseTable("https://www.qnap.com/en/security-advisories?ref=security_advisory_details");
        List<CompositeVulnerability> vulnerabilities = parser.parseWebPage("https://www.qnap.com/en/security-advisories?ref=security_advisory_details", null);

        assertTrue(vulnerabilities.size() > 190);
        CompositeVulnerability vuln = getVulnerability(vulnerabilities, "CVE-2023-22809");
        assertNotNull(vuln);
        assertEquals("2023-04-20", vuln.getPublishDate());
        assertTrue(vuln.getDescription().contains("A vulnerability has been reported in sudo. The vulnerability affects the following QNAP operating system"));
        assertFalse(vuln.getDescription().contains("Multiple vulnerabilities have been reported in OpenSSL. These vulnerabilities affect the following QNAP operating systems: QTS, QuTS hero, QuTScloud, QVP (QVR Pro appliances), QVR, QES"));
    }

    @Test
    public void testParseTableVMWare() {
        ParseTable parser = new ParseTable("https://www.vmware.com/security/advisories.html");
        List<CompositeVulnerability> vulnerabilities = parser.parseWebPage("https://www.vmware.com/security/advisories.html", null);

        assertTrue(vulnerabilities.size() > 80);
        CompositeVulnerability vuln = getVulnerability(vulnerabilities, "CVE-2021-22035");
        assertNotNull(vuln);
        assertTrue(vuln.getPublishDate().equals("12-10-2021") || vuln.getPublishDate().equals("11-10-2021"));
        assertTrue(vuln.getDescription().contains("VMware vRealize Log Insight"));
        assertFalse(vuln.getDescription().contains("VMware Aria Operations for"));
    }

    @Test
    public void testParseTableNvidia() {
        ParseTable parser = new ParseTable("https://www.nvidia.com/en-us/security/");
        List<CompositeVulnerability> vulnerabilities = parser.parseWebPage("https://www.nvidia.com/en-us/security/", null);

        assertTrue(vulnerabilities.size() > 400);
        CompositeVulnerability vuln = getVulnerability(vulnerabilities, "CVE-2017-5715");
        assertNotNull(vuln);
        assertEquals("16 Oct 2018", vuln.getPublishDate());
        assertTrue(vuln.getDescription().contains("NVIDIA SHIELD TV – October 2018"));
        assertFalse(vuln.getDescription().contains("NVIDIA Shield TV Security Updates for CPU Speculative Side Channel Vulnerabilities"));
    }
}
