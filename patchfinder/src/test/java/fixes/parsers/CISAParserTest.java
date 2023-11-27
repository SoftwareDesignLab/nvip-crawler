package fixes.parsers;

public class CISAParserTest extends FixParserTest<CISAParser> {
    public CISAParserTest() {
        // TODO: Initialize with test values
        this.setFixParser(getNewParser("", ""));
    }

    @Override
    protected CISAParser getNewParser(String cveId, String url) {
        return new CISAParser(cveId, url);
    }

    @Override
    public void testParseWebpage() {
        // TODO: Test parseWebpage
    }
}
