package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.Test;
import java.util.List;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.*;

public class ParseTableTest extends AbstractParserTest {

    @Test
    public void testParseTable() {
        ParseTable parser = new ParseTable("https://www.qnap.com/en/security-advisories?ref=security_advisory_details");
        List<CompositeVulnerability> vulnerabilities = parser.parseWebPage("https://www.qnap.com/en/security-advisories?ref=security_advisory_details", null);

        assertEquals(213, vulnerabilities.size());
        CompositeVulnerability vuln = getVulnerability(vulnerabilities, "CVE-2023-22809");
        assertNotNull(vuln);
        assertEquals("2023-03-30", vuln.getPublishDate());
        assertTrue(vuln.getDescription().contains("A vulnerability has been reported in sudo. The vulnerability affects the following QNAP operating system"));
        assertFalse(vuln.getDescription().contains("Multiple vulnerabilities have been reported in OpenSSL. These vulnerabilities affect the following QNAP operating systems: QTS, QuTS hero, QuTScloud, QVP (QVR Pro appliances), QVR, QES"));
    }
}
