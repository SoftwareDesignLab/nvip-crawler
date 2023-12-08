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


import edu.rit.se.nvip.db.model.Fix;
import org.jsoup.Jsoup;
import org.junit.Test;

import java.util.HashSet;
import java.util.Set;

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

        Set<Fix> actual =  this.fixParser().parse();
        Set <Fix> expected = new HashSet<>();

        assertEquals(expected, actual);
    }
}
