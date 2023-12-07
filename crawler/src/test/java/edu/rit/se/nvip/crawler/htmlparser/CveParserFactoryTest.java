/ **
* Copyright 2021 Rochester Institute of Technology (RIT). Developed with
* government support under contract 70RCSA22C00000008 awarded by the United
* States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the “Software”), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
* /

/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RCSA22C00000008 awarded by the United
 * States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.for Cybersecurity and Infrastructure Security Agency.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.db.model.RawVulnerability;
import edu.rit.se.nvip.crawler.SeleniumDriver;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;

//TODO: Remove some of these tests as they are redundant. Other tests address this functionality
@ExtendWith(MockitoExtension.class)
public class CveParserFactoryTest extends AbstractParserTest{

    @Mock
    static SeleniumDriver driver;
    CveParserFactory parserFactory = new CveParserFactory();
    AbstractCveParser parser;

    @Test
    public void testFactoryTenable() {
        String html = safeReadHtml("src/test/resources/test-tenable.html");
        String sSourceURL = "https://www.tenable.com/cve/CVE-2022-21953";
        parser = parserFactory.createParser(sSourceURL, driver);
        assertNotNull(parser);
        assertEquals(parser.getClass(), TenableCveParser.class);
        List<RawVulnerability> list = parser.parseWebPage(sSourceURL, html);
        assertEquals(1, list.size());
        RawVulnerability vuln = list.get(0);
        assertEquals("CVE-2022-21953", vuln.getCveId());
        assertEquals("2023-02-07 00:00:00", vuln.getPublishDateString());
        assertEquals(TenableCveParserTest.TEST_DESCRIPTION, vuln.getDescription());
    }

    @Test
    public void testFactoryTenableSec() {
        String html = safeReadHtml("src/test/resources/test-tenable-security.html");
        String sSourceURL = "https://www.tenable.com/security/research/tra-2023-5";
        parser = parserFactory.createParser(sSourceURL, driver);
        assertNotNull(parser);
        assertEquals(parser.getClass(), TenableSecurityParser.class);
        List<RawVulnerability> list = parser.parseWebPage(sSourceURL, html);
        assertEquals(1, list.size());
        RawVulnerability vuln = list.get(0);
        assertEquals("CVE-2023-0587", vuln.getCveId());
        assertEquals("2023-01-30 00:00:00", vuln.getPublishDateString());
        assertTrue(vuln.getDescription().contains("A file upload vulnerability in exists in Trend Micro Apex One"));
        assertFalse(vuln.getDescription().contains("View More Research Advisories"));
    }

    @Test
    public void testFactoryExploitDB() {
        String html = safeReadHtml("src/test/resources/test-exploit-db.html");
        String sSourceURL = "https://www.exploit-db.com/exploits/51031";
        parser = parserFactory.createParser(sSourceURL, driver);
        assertNotNull(parser);
        assertEquals(parser.getClass(), ExploitDBParser.class);
        List<RawVulnerability> list = parser.parseWebPage(sSourceURL, html);
        assertEquals(1, list.size());
        RawVulnerability vuln = list.get(0);
        assertEquals("CVE-2022-37661", vuln.getCveId());
        assertEquals("2022-11-11 00:00:00", vuln.getPublishDateString());
        assertTrue(vuln.getDescription().contains("Remote Code Execution"));
    }

    @Test
    public void testFactoryKbCert() {
        String html = safeReadHtml("src/test/resources/test-kb-cert-single.html");
        String sSourceURL = "https://www.kb.cert.org/vuls/id/434994";
        parser = parserFactory.createParser(sSourceURL, driver);
        assertNotNull(parser);
        assertEquals(parser.getClass(), KbCertCveParser.class);
        List<RawVulnerability> list = parser.parseWebPage(sSourceURL, html);
        assertEquals(1, list.size());
        RawVulnerability vuln = list.get(0);
        assertEquals("CVE-2021-33164", vuln.getCveId());
        assertTrue(vuln.getDescription().contains("access and validation of the SMRAM"));
        assertEquals("2022-11-08 00:00:00", vuln.getPublishDateString());
    }

    @Test
    public void testFactoryPacketStorm() {
        String html = safeReadHtml("src/test/resources/test-packetstorm-files-2.html");
        String sSourceURL = "https://packetstormsecurity.com/files/170988/Cisco-RV-Series-Authentication-Bypass-Command-Injection.html";
        parser = parserFactory.createParser(sSourceURL, driver);
        assertNotNull(parser);
        assertEquals(parser.getClass(), PacketStormParser.class);
        List<RawVulnerability> list = parser.parseWebPage(sSourceURL, html);
        assertEquals(2, list.size());
        RawVulnerability vuln = getVulnerability(list, "CVE-2022-20705");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("Cisco RV160, RV260, RV340, and RV345 Small Business Routers, allowing attackers to execute arbitrary commands"));
        assertEquals("2023-02-14 00:00:00", vuln.getPublishDateString());
    }

    @Test
    public void testFactoryTalos() {
        String html = safeReadHtml("src/test/resources/test-talos.html");
        String sSourceURL = "https://talosintelligence.com/vulnerability_reports/TALOS-2020-1124";
        parser = parserFactory.createParser(sSourceURL, driver);
        assertNotNull(parser);
        assertEquals(parser.getClass(), TalosIntelligenceParser.class);
        List<RawVulnerability> list = parser.parseWebPage(sSourceURL, html);
        assertEquals(1, list.size());
        RawVulnerability vuln = list.get(0);
        assertEquals("CVE-2022-40224", vuln.getCveId());
        assertEquals("2022-10-14 00:00:00", vuln.getPublishDateString());
        assertTrue(vuln.getDescription().contains("A denial of service vulnerability exists"));
    }

    @Test
    public void testFactoryGentooBugs() {
        String html = safeReadHtml("src/test/resources/test-bugs-gentoo-single-cve.html");
        String sSourceURL = "https://bugs.gentoo.org/600624";
        parser = parserFactory.createParser(sSourceURL, driver);
        assertNotNull(parser);
        assertEquals(parser.getClass(), BugsGentooParser.class);
        List<RawVulnerability> list = parser.parseWebPage(sSourceURL, html);
        assertEquals(1, list.size());
        RawVulnerability vuln = list.get(0);
        assertEquals("CVE-2013-4392", vuln.getCveId());
    }

    @Test
    public void testFactoryGentooSecurity() {
        String html = safeReadHtml("src/test/resources/test-security-gentoo-single.html");
        String sSourceURL = "https://security.gentoo.org/glsa/200502-21";
        parser = parserFactory.createParser(sSourceURL, driver);
        assertNotNull(parser);
        assertEquals(parser.getClass(), SecurityGentooParser.class);
        List<RawVulnerability> list = parser.parseWebPage(sSourceURL, html);
        assertEquals(1, list.size());
        RawVulnerability vuln = list.get(0);
        assertEquals("CVE-2005-0453", vuln.getCveId());
    }

    @Test
    public void testFactoryVMWare() {
        String html = safeReadHtml("src/test/resources/test-vmware-advisories-single-cve.html");
        String sSourceURL = "https://www.vmware.com/security/advisories/VMSA-2023-0003.html";
        parser = parserFactory.createParser(sSourceURL, driver);
        assertNotNull(parser);
        assertEquals(parser.getClass(), VMWareAdvisoriesParser.class);
        List<RawVulnerability> list = parser.parseWebPage(sSourceURL, html);
        assertEquals(1, list.size());
        RawVulnerability vuln = list.get(0);
        assertEquals("CVE-2023-20854", vuln.getCveId());
    }

    @Test
    public void testFactoryBugzilla() {
        String html = safeReadHtml("src/test/resources/test-bugzilla-cvedetail-2.html");
        String sSourceURL = "https://bugzilla.redhat.com/show_bug.cgi?id=1576652";
        parser = parserFactory.createParser(sSourceURL, driver);
        assertNotNull(parser);
        assertEquals(parser.getClass(), BugzillaParser.class);
        List<RawVulnerability> list = parser.parseWebPage(sSourceURL, html);
        assertEquals(1, list.size());
        RawVulnerability vuln = list.get(0);
        assertEquals("CVE-2018-3736", vuln.getCveId());
    }

    @Test
    public void testFactorySecLists() {
        String html = safeReadHtml("src/test/resources/test-seclist.html");
        String sSourceURL = "https://seclists.org/bugtraq/2016/Feb/147";
        parser = parserFactory.createParser(sSourceURL, driver);
        assertNotNull(parser);
        assertEquals(parser.getClass(), SeclistsParser.class);
        List<RawVulnerability> list = parser.parseWebPage(sSourceURL, html);
        assertEquals(1, list.size());
        RawVulnerability vuln = list.get(0);
        assertEquals("CVE-2016-0763", vuln.getCveId());
    }

    @Test
    public void testFactoryRedhat() {
        String html = safeReadHtml("src/test/resources/test-redhat-security-2.html");
        String sSourceURL = "https://access.redhat.com/security/cve/cve-2023-25725";
        parser = parserFactory.createParser(sSourceURL, driver);
        assertNotNull(parser);
        assertEquals(parser.getClass(), RedHatParser.class);
        List<RawVulnerability> list = parser.parseWebPage(sSourceURL, html);
        assertEquals(1, list.size());
        RawVulnerability vuln = list.get(0);
        assertEquals("CVE-2023-25725", vuln.getCveId());
    }

    @Test
    public void testFactoryBosch() {
        String html = safeReadHtml("src/test/resources/test-bosch-security-2.html");
        String sSourceURL = "https://psirt.bosch.com/security-advisories/bosch-sa-464066-bt.html";
        parser = parserFactory.createParser(sSourceURL, driver);
        assertNotNull(parser);
        assertEquals(parser.getClass(), BoschSecurityParser.class);
        List<RawVulnerability> list = parser.parseWebPage(sSourceURL, html);
        assertEquals(1, list.size());
        RawVulnerability vuln = list.get(0);
        assertEquals("CVE-2022-32540", vuln.getCveId());
    }

    @Test
    public void testFactoryGoogleCloud() {
        String html = safeReadHtml("src/test/resources/test-google-cloud-bulletin.html");
        String sSourceURL = "https://cloud.google.com/support/bulletins";
        parser = parserFactory.createParser(sSourceURL, driver);
        assertNotNull(parser);
        assertEquals(parser.getClass(), GoogleCloudParser.class);
        assertNotEquals(parser.parseWebPage(sSourceURL, html).size(), 0);
    }

    @Test
    public void testFactoryCurl() {
        String html = safeReadHtml("src/test/resources/test-curl.html");
        String sSourceURL = "https://curl.se";
        parser = parserFactory.createParser(sSourceURL, driver);
        assertNotNull(parser);
        assertEquals(parser.getClass(), CurlParser.class);
        assertNotEquals(parser.parseWebPage(sSourceURL, html).size(), 0);
    }

    @Test
    public void testFactoryNull() {
        parser = parserFactory.createParser(null, driver);
        assertNotNull(parser);
        assertEquals(parser.getClass(), NullParser.class);
        parser = parserFactory.createParser("gentoo......news", driver);
        assertNotNull(parser);
        assertEquals(parser.getClass(), NullParser.class);
        parser = parserFactory.createParser("gentoo......blogs", driver);
        assertNotNull(parser);
        assertEquals(parser.getClass(), NullParser.class);
        parser = parserFactory.createParser("mitre.org", driver);
        assertNotNull(parser);
        assertEquals(parser.getClass(), NullParser.class);
        parser = parserFactory.createParser("nist.gov", driver);
        assertNotNull(parser);
        assertEquals(parser.getClass(), NullParser.class);

    }
}
