package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.db.model.RawVulnerability;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.junit.Test;

import java.util.List;
import java.time.LocalDate;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.*;

public class ParseCVEDescriptionTest extends AbstractParserTest {
    private final Logger logger = LogManager.getLogger(getClass().getSimpleName());

    @Test
    public void testParseCVEDescriptionCreston() {
        String html = safeReadHtml("src/test/resources/test-generic_description_parser-creston.html");
        ParseCVEDescription parser = new ParseCVEDescription("https://www.crestron.com/Security/Security_Advisories");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://www.crestron.com/Security/Security_Advisories",
                html
        );

        assertTrue(list.size() > 9);
        RawVulnerability vuln = getVulnerability(list, "CVE-2023-1017");
        assertNotNull(vuln);
        String current_date = LocalDate.now() + " 00:00:00";
        assertEquals(current_date, vuln.getPublishDate());
        assertTrue(vuln.getDescription().contains("Crestron is aware of an issue with TPM’s 2.0 Module Library in which an out of bounds attack can be executed"));
    }

    @Test
    public void testParseCVEDescriptionDalhua() {
        String html = safeReadHtml("src/test/resources/test-generic_description_parser-dahuas.html");
        ParseCVEDescription parser = new ParseCVEDescription("https://www.dahuasecurity.com/support/cybersecurity/details/1147");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://www.dahuasecurity.com/support/cybersecurity/details/1147",
                html
        );

        assertEquals(1, list.size());
        RawVulnerability vuln = getVulnerability(list, "CVE-2022-30564");
        assertNotNull(vuln);
        String current_date = LocalDate.now() + " 00:00:00";
        assertEquals(current_date, vuln.getPublishDate());
        assertTrue(vuln.getDescription().contains("Some Dahua embedded products have a vulnerability of unauthorized modification of the device timestamp. "));
    }

    @Test
    public void testParseCVEDescriptionFluidAttacks() {
        String html = safeReadHtml("src/test/resources/test-generic_description_parser-fluidattacks.html");
        ParseCVEDescription parser = new ParseCVEDescription("https://fluidattacks.com/advisories/napoli/");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://fluidattacks.com/advisories/napoli/",
                html
        );

        assertTrue(list.size() > 5);
        RawVulnerability vuln = getVulnerability(list, "CVE-2023-1031");
        assertNotNull(vuln);
        String current_date = LocalDate.now() + " 00:00:00";
        assertEquals(current_date, vuln.getPublishDate());
        assertTrue(vuln.getDescription().contains("MonicaHQ version 4.0.0 allows an authenticated remote attacker to execute malicious code in the application."));
    }

    @Test
    public void testParseCVEDescriptionGrafana() {
        String html = safeReadHtml("src/test/resources/test-generic_description_parser-grafana.html");
        ParseCVEDescription parser = new ParseCVEDescription("https://grafana.com/security/security-advisories/cve-2022-21673/");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://grafana.com/security/security-advisories/cve-2022-21673/",
                html
        );

        assertEquals(1, list.size());
        RawVulnerability vuln = getVulnerability(list, "CVE-2022-21673");
        assertNotNull(vuln);
        String current_date = LocalDate.now() + " 00:00:00";
        assertEquals(current_date, vuln.getPublishDate());
        assertTrue(vuln.getDescription().contains("In affected versions when a data source has the Forward OAuth Identity feature enabled, sending a query to that datasource with an API token"));
    }

    @Test
    public void testParseCVEDescriptionJenkins() {
        String html = safeReadHtml("src/test/resources/test-generic_description_parser-jenkins.html");
        ParseCVEDescription parser = new ParseCVEDescription("https://www.jenkins.io/security/advisory/2023-05-16/");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://www.jenkins.io/security/advisory/2023-05-16/",
                html
        );

        assertTrue(list.size() > 20);
        RawVulnerability vuln = getVulnerability(list, "CVE-2023-32978");
        assertNotNull(vuln);
        String current_date = LocalDate.now() + " 00:00:00";
        assertEquals(current_date, vuln.getPublishDate());
        assertTrue(vuln.getDescription().contains("LDAP Plugin 673.v034ec70ec2b_b_ and earlier does not require POST requests for a form validation method, resulting in a cross-site request forgery (CSRF) vulnerability"));
    }

    @Test
    public void testParseCVEDescriptionMFiles() {
        String html = safeReadHtml("src/test/resources/test-generic_description_parser-mfiles.html");
        ParseCVEDescription parser = new ParseCVEDescription("https://www.m-files.com/about/trust-center/security-advisories/cve-2023-0383/");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://www.m-files.com/about/trust-center/security-advisories/cve-2023-0383/",
                html
        );

        assertEquals(1, list.size());
        RawVulnerability vuln = getVulnerability(list, "CVE-2023-0383");
        assertNotNull(vuln);
        String current_date = LocalDate.now() + " 00:00:00";
        assertEquals(current_date, vuln.getPublishDate());
        assertTrue(vuln.getDescription().contains("User-controlled operations could have allowed Denial of Service in M-Files Server before 23.4.12528.1 due to uncontrolled memory consumption."));
    }

    @Test
    public void testParseCVEDescriptionNetskope() {
        String html = safeReadHtml("src/test/resources/test-generic_description_parser-netskope.html");
        ParseCVEDescription parser = new ParseCVEDescription("https://www.netskope.com/company/security-compliance-and-assurance/security-advisories-and-disclosures/netskope-security-advisory-nskpsa-2022-001");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://www.netskope.com/company/security-compliance-and-assurance/security-advisories-and-disclosures/netskope-security-advisory-nskpsa-2022-001",
                html
        );

        assertEquals(1, list.size());
        RawVulnerability vuln = getVulnerability(list, "CVE-2021-44862");
        assertNotNull(vuln);
        String current_date = LocalDate.now() + " 00:00:00";
        assertEquals(current_date, vuln.getPublishDate());
        assertTrue(vuln.getDescription().contains("Netskope client is impacted by a vulnerability where an authenticated, local attacker can view sensitive information stored in NSClient logs which should be restricted"));
    }

    @Test
    public void testParseCVEDescriptionNozomi() {
        String html = safeReadHtml("src/test/resources/test-generic_description_parser-nozomi.html");
        ParseCVEDescription parser = new ParseCVEDescription("https://security.nozominetworks.com/NN-2023:1-01");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://security.nozominetworks.com/NN-2023:1-01",
                html
        );

        assertEquals(1, list.size());
        RawVulnerability vuln = getVulnerability(list, "CVE-2022-4259");
        assertNotNull(vuln);
        String current_date = LocalDate.now() + " 00:00:00";
        assertEquals(current_date, vuln.getPublishDate());
        assertTrue(vuln.getDescription().contains("A SQL Injection vulnerability in Nozomi Networks Guardian and CMC, due to improper input validation in the Alerts controller"));
    }

    @Test
    public void testParseCVEDescriptionProofPoint() {
        String html = safeReadHtml("src/test/resources/test-generic_description_parser-proofpoint.html");
        ParseCVEDescription parser = new ParseCVEDescription("https://www.proofpoint.com/us/security/security-advisories/pfpt-sa-2023-0001");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://www.proofpoint.com/us/security/security-advisories/pfpt-sa-2023-0001",
                html
        );

        assertEquals(2, list.size());
        RawVulnerability vuln = getVulnerability(list, "CVE-2023-0089");
        assertNotNull(vuln);
        String current_date = LocalDate.now() + " 00:00:00";
        assertEquals(current_date, vuln.getPublishDate());
        assertTrue(vuln.getDescription().contains("CVE-2023-0089 describes a vulnerability which allows for remote code execution by an authenticated user"));
    }

    @Test
    public void testParseCVEDescriptionJoomla() {
        String html = safeReadHtml("src/test/resources/test-generic_description_parser-joomla.html");
        ParseCVEDescription parser = new ParseCVEDescription("https://developer.joomla.org/security-centre.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://developer.joomla.org/security-centre.html",
                html
        );

        assertTrue(list.size() > 9);
        RawVulnerability vuln = getVulnerability(list, "CVE-2022-27914");
        assertNotNull(vuln);
        String current_date = LocalDate.now() + " 00:00:00";
        assertEquals(current_date, vuln.getPublishDate());
        assertTrue(vuln.getDescription().contains("Inadequate filtering of potentially malicious user input leads to reflected XSS vulnerabilities in com_media"));
    }
}