package fixes.parsers;

import fixes.Fix;
import org.junit.Test;

import java.util.List;

public class CXSecurityParserTest extends FixParserTest<CXSecurityParser> {
    public CXSecurityParserTest() {
        // TODO: Initialize with test values
        this.setFixParser(getNewParser("", ""));
    }

    @Override
    protected CXSecurityParser getNewParser(String cveId, String url) {
        return new CXSecurityParser(cveId, url);
    }

    @Override
    public void testParseWebpage() {
        // TODO: Test parseWebpage
        final List<Fix> fixes = this.fixParser().parse();
    }

    @Test
    public void testParseWebpageNoFixes() {
        // TODO: Test parseWebpage with second cve/url
        this.setFixParser(getNewParser("", ""));
        final List<Fix> fixes = this.fixParser().parse();
    }
}
