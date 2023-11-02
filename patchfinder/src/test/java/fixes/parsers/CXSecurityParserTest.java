package fixes.parsers;

import fixes.Fix;
import org.jsoup.Jsoup;
import org.junit.Test;

import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import static org.junit.Assert.assertEquals;

public class CXSecurityParserTest extends FixParserTest<CXSecurityParser> {
    public CXSecurityParserTest() {
        // TODO: Initialize with test values
//        this.setFixParser(getNewParser("", ""));
    }

    @Override
    protected CXSecurityParser getNewParser(String cveId, String url) {
        return new CXSecurityParser(cveId, url);
    }

    @Override
    //zero fixes are found
    public void testParseWebpage() {
        // TODO: Test parseWebpage
    }

    @Test
    public void testParseWebpageNoFixes() {
        // TODO: Test parseWebpage with second cve/url
        String cveId ="CVE-2023-3990";
        String url ="https://cxsecurity.com/cveshow/CVE-2023-3990";
        this.setFixParser(getNewParser(cveId, url));

        List <Fix> actual =  this.fixParser().parse();
        List <Fix> expected = new ArrayList<>();

        assertEquals(expected, actual);
    }
}
