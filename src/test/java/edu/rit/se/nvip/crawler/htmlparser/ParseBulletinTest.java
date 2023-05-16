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
    // taken from AndroidParserTest TODO: combine with AndroidParserTest
    @Test
    public void testParseBulletinAndroid() {
        ParseBulletin parser = new ParseBulletin("https://source.android.com/docs/security/bulletin/2023-02-01");
        String html = safeReadHtml("src/test/resources/test-android-bulletin.html");
        List<CompositeVulnerability> list = parser.parseWebPage(
                "https://source.android.com/docs/security/bulletin/2023-02-01",
                html
        );
        assertEquals(40, list.size());
        CompositeVulnerability vuln = getVulnerability(list, "CVE-2023-20933");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("with no additional execution privileges needed"));
        assertEquals("February 6, 2023", vuln.getPublishDate());
    }


    // test against Google Cloud Bulletin
    // taken from GoogleCloudBulletinTest TODO: combine with GoogleCloudBulletinTest
    @Test
    public void testParseBulletinGoogle() throws IOException {
        String html = FileUtils.readFileToString(new File("src/test/resources/test-google-cloud-bulletin.html"), StandardCharsets.US_ASCII);
        ParseBulletin parser = new ParseBulletin("https://cloud.google.com/support/bulletins/");
        List<CompositeVulnerability> list = parser.parseWebPage("https://cloud.google.com/support/bulletins", html);

        assertTrue(list.size() > 90);
        CompositeVulnerability vuln1 = getVulnerability(list, "CVE-2022-3786");
        CompositeVulnerability vuln6 = getVulnerability(list, "CVE-2022-2588");
        assertNotNull(vuln1);
        assertNotNull(vuln6);
        assertEquals("2023-01-11", vuln1.getPublishDate());
        assertEquals("2023-01-11", vuln1.getLastModifiedDate());
        assertTrue(vuln1.getDescription().contains("OpenSSL v3.0.6 that can potentially cause a crash."));
        assertEquals("2022-11-09", vuln6.getPublishDate());
        assertTrue(vuln6.getDescription().contains("Linux kernel that can lead to a full container break out to root on the node."));
    }
}
