package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.RawVulnerability;
import edu.rit.se.nvip.crawler.SeleniumDriver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@Disabled("Disabled until selenium driver can be properly mocked")
@ExtendWith(MockitoExtension.class)
public class ParseAccordionTest extends AbstractParserTest{

    @Mock
    private static SeleniumDriver driver;

    @Test
    public void testParseAccordionNi() {

        ParseAccordion parser = new ParseAccordion("https://www.ni.com/en-us/support/documentation/supplemental/11/available-critical-and-security-updates-for-ni-software.html", driver);
        List<RawVulnerability> vulnerabilities = parser.parseWebPage("https://www.ni.com/en-us/support/documentation/supplemental/11/available-critical-and-security-updates-for-ni-software.html", null);

        assertTrue(vulnerabilities.size() > 0);
        RawVulnerability vuln = getVulnerability(vulnerabilities, "CVE-2022-42718");
        assertNotNull(vuln);
        assertEquals("2022-12-01 00:00:00", vuln.getPublishDate());
        assertTrue(vuln.getDescription().contains("Incorrect default permissions in the installation folder for NI LabVIEW"));
        assertFalse(vuln.getDescription().contains("An update is available for FlexLogger 2019"));
    }

    @Test
    public void testParseAccordionOpenVPN() {
        ParseAccordion parser = new ParseAccordion("https://openvpn.net/security-advisories/", driver);
        List<RawVulnerability> vulnerabilities = parser.parseWebPage("https://openvpn.net/security-advisories/", null);

        assertTrue(vulnerabilities.size() > 0);
        RawVulnerability vuln = getVulnerability(vulnerabilities, "CVE-2022-3602");
        assertNotNull(vuln);
        assertEquals("2022-11-01 00:00:00", vuln.getPublishDate());
        assertTrue(vuln.getDescription().contains("OpenVPN Access Server uses the OpenSSL library that comes with the operating system. On most operating systems this is"));
        assertFalse(vuln.getDescription().contains("Our OpenVPN Connect v2 and v3 client software for macOS is signed using our official digital signature"));
    }

    @Test
    public void testParseAccordionPega() {
        ParseAccordion parser = new ParseAccordion("https://www.pega.com/trust/security-bulletins", driver);
        List<RawVulnerability> vulnerabilities = parser.parseWebPage("https://www.pega.com/trust/security-bulletins", null);

        assertTrue(vulnerabilities.size() > 0);
        RawVulnerability vuln = getVulnerability(vulnerabilities, "CVE-2022-23531");
        assertNotNull(vuln);
        assertEquals("2023-03-16 00:00:00", vuln.getPublishDate());
        assertTrue(vuln.getDescription().contains("Three vulnerabilities were recently identified in the JsonWebToken software that could lead to unintended actions"));
        assertFalse(vuln.getDescription().contains("A bad actor with non-admin user access to a client desktop, with Pega Synchronization Engine"));
    }

    @Test
    public void testParseAccordionAsus() {
        ParseAccordion parser = new ParseAccordion("https://www.asus.com/content/asus-product-security-advisory/", driver);
        List<RawVulnerability> vulnerabilities = parser.parseWebPage("https://www.asus.com/content/asus-product-security-advisory/", null);

        assertTrue(vulnerabilities.size() > 0);
        RawVulnerability vuln = getVulnerability(vulnerabilities, "CVE-2020-24588");
        assertNotNull(vuln);
        assertEquals("2021-05-24 00:00:00", vuln.getPublishDate());
        assertTrue(vuln.getDescription().contains("ASUS is aware of newly discovered industry-wide WiFi protocol vulnerabilities that affect every brand of WiFi router. The vulnerabilities are known as Fragmentation"));
        assertFalse(vuln.getDescription().contains("ASUS has released the new BIOS version 303 for the ASUS ZenBook Pro Duo 15 OLED (UX582LR) laptop, which includes important security updates"));
    }
}
