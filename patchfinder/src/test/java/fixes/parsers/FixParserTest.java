package fixes.parsers;

import env.FixFinderEnvVars;
import org.junit.jupiter.api.Test;

import java.io.IOException;
public abstract class FixParserTest<T extends FixParser> {
    private T fixParser;

    protected FixParserTest() {
//        this.fixParser = fixParser;
        FixFinderEnvVars.initializeEnvVars(true);
    }

    public T fixParser() { return fixParser; }

    public void setFixParser(T fixParser) { this.fixParser = fixParser; }

    protected abstract T getNewParser(String cveId, String url);

    @Test
    public abstract void testParseWebpage() throws IOException;

    @Test
    public void testParse() {
        // TODO: Test parse
    }

    @Test
    public void testGetParser() {
        // TODO: Test getParser
    }
}
