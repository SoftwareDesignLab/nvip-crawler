package fixes.parsers;

import env.FixFinderEnvVars;
import org.junit.Test;

public abstract class FixParserTest<T extends FixParser> {
    final protected T fixParser;

    protected FixParserTest(T fixParser) {
        this.fixParser = fixParser;
        FixFinderEnvVars.initializeEnvVars(true);
    }

    @Test
    public abstract void testParseWebpage();

    @Test
    public void testParse() {
        // TODO: Test parse
    }

    @Test
    public void testGetParser() {
        // TODO: Test getParser
    }
}
