package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.db.model.RawVulnerability;
import edu.rit.se.nvip.crawler.SeleniumDriver;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@Disabled("Disabled until selenium driver can be properly mocked")
public class ParseTableTest extends AbstractParserTest {

    @Test
    public void testParseTableQNAP() {
        SeleniumDriver driver = mock(SeleniumDriver.class);

        ParseTable parser = new ParseTable("https://www.qnap.com/en/security-advisories?ref=security_advisory_details", driver);
        List<RawVulnerability> vulnerabilities = parser.parseWebPage("https://www.qnap.com/en/security-advisories?ref=security_advisory_details", null);

        assertTrue(vulnerabilities.size() > 190);
        RawVulnerability vuln = getVulnerability(vulnerabilities, "CVE-2023-22809");
        assertNotNull(vuln);
        assertEquals("2023-06-15 00:00:00", vuln.getPublishDateString());
        assertTrue(vuln.getDescription().contains("A vulnerability has been reported in sudo. The vulnerability affects the following QNAP operating system"));
        assertFalse(vuln.getDescription().contains("Multiple vulnerabilities have been reported in OpenSSL. These vulnerabilities affect the following QNAP operating systems: QTS, QuTS hero, QuTScloud, QVP (QVR Pro appliances), QVR, QES"));
    }

    @Test
    public void testParseTableVMWare() {
        SeleniumDriver driver = mock(SeleniumDriver.class);

        ParseTable parser = new ParseTable("https://www.vmware.com/security/advisories.html", driver);
        List<RawVulnerability> vulnerabilities = parser.parseWebPage("https://www.vmware.com/security/advisories.html", null);

        assertTrue(vulnerabilities.size() > 70);
        RawVulnerability vuln = getVulnerability(vulnerabilities, "CVE-2021-22035");
        assertNotNull(vuln);
        assertTrue(vuln.getPublishDateString().equals("2021-10-11 00:00:00") || vuln.getPublishDateString().equals("2021-10-12 00:00:00"));
        assertTrue(vuln.getDescription().contains("VMware vRealize Log Insight"));
        assertFalse(vuln.getDescription().contains("VMware Aria Operations for"));
    }

    @Test
    public void testParseTableNvidia() {
        SeleniumDriver driver = mock(SeleniumDriver.class);

        ParseTable parser = new ParseTable("https://www.nvidia.com/en-us/security/", driver);
        List<RawVulnerability> vulnerabilities = parser.parseWebPage("https://www.nvidia.com/en-us/security/", null);

        assertTrue(vulnerabilities.size() > 400);
        RawVulnerability vuln = getVulnerability(vulnerabilities, "CVE-2017-5715");
        assertNotNull(vuln);
        assertEquals("2018-10-16 00:00:00", vuln.getPublishDateString());
        assertTrue(vuln.getDescription().contains("NVIDIA SHIELD TV – October 2018"));
        assertFalse(vuln.getDescription().contains("NVIDIA Shield TV Security Updates for CPU Speculative Side Channel Vulnerabilities"));
    }
}
