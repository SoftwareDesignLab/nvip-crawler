package edu.rit.se.nvip.crawler.htmlparser;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.apache.commons.io.FileUtils;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.*;

public class ParseBulletinTest extends AbstractParserTest {

    // test against Android Bulletin
    // take from AndroidParserTest
    @Test
    public void testParseBulletinAndroid() {
        ParseBulletin parser = new ParseBulletin("https://source.android.com/docs/security/bulletin/2023-02-01");
        String html = safeReadHtml("src/test/resources/test-android-bulletin.html");
        List<CompositeVulnerability> list = parser.parseWebPage(
                "https://source.android.com/docs/security/bulletin/2023-02-01",
                html
        );
        assertEquals(40, list.size());
        CompositeVulnerability vuln = list.get(8);
        assertEquals("CVE-2023-20933", vuln.getCveId());
        assertTrue(vuln.getDescription().contains("local escalation of privilege with no additional execution privileges needed"));
        assertFalse(vuln.getDescription().contains("lead to remote code execution with no additional"));
        assertEquals("February 6, 2023", vuln.getPublishDate());
        assertEquals("February 8, 2023", vuln.getLastModifiedDate());
    }


    // test against Google Cloud Bulletin
    // take from GoogleCloudBulletinTest
    @Test
    public void testParseBulletinGoogle() throws IOException {
        String html = FileUtils.readFileToString(new File("src/test/resources/test-google-cloud-bulletin.html"), StandardCharsets.US_ASCII);
        ParseBulletin parser = new ParseBulletin("https://cloud.google.com/support/bulletins/");
        List<CompositeVulnerability> list = parser.parseWebPage("https://cloud.google.com/support/bulletins", html);

        assertEquals(52, list.size());
        CompositeVulnerability vuln1 = list.get(0);
        CompositeVulnerability vuln6 = list.get(5);

        assertEquals("CVE-2022-3786", vuln1.getCveId());
        assertEquals("2023-01-11", vuln1.getPublishDate());
        assertEquals("2023-01-11", vuln1.getLastModifiedDate());
        assertTrue(vuln1.getDescription().contains("OpenSSL v3.0.6 that can potentially cause a crash."));
        assertEquals("CVE-2022-2588", vuln6.getCveId());
        assertEquals("2022-11-09", vuln6.getPublishDate());
        assertEquals("2023-01-19", vuln6.getLastModifiedDate());
        assertTrue(vuln6.getDescription().contains("Linux kernel that can lead to a full container break out to root on the node."));
    }
}
