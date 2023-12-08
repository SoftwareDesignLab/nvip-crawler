/**
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
*/

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
