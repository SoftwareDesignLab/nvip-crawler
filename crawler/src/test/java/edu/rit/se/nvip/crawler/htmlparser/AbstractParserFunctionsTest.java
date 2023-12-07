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

package edu.rit.se.nvip.crawler.htmlparser;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class AbstractParserFunctionsTest extends AbstractParserTest {

    // init a Generic Parser to test protected methods
    ParseList parser = new ParseList("");

    String text = "This is a test string with description text that the parser will extract" +
            " the extracted ....Published: 05-21-2023 ......text might contain anything but we are " +
            "only interested in the date located 91 characters into the string";

    @Test
    public void testSubstringBoundsForExtractDate() {
        int[] bounds = parser.getSubstringBounds(text, "published");
        assertEquals(91, bounds[0]);
        assertEquals(131, bounds[1]);
    }

    @Test
    public void testExtractDate() {
        // published branch
        GenericDate date = parser.extractDate(text);
        assertEquals("05-21-2023", date.getRawDate());
        // created branch
        GenericDate createdDate = parser.extractDate(text.replace("Published:", "Created:"));
        assertEquals("05-21-2023", createdDate.getRawDate());
        // fall through branch
        GenericDate descDate = parser.extractDate(text.replace("Published:", ""));
        assertEquals("05-21-2023", descDate.getRawDate());
    }

    @Test
    public void testExtractLastModifiedDate() {
        // last modified branch
        GenericDate date = parser.extractLastModifiedDate(text.replace("Published:", "Last Modified:"));
        assertEquals("05-21-2023", date.getRawDate());
        // last updated branch
        GenericDate createdDate = parser.extractLastModifiedDate(text.replace("Published:", "Last Updated:"));
        assertEquals("05-21-2023", createdDate.getRawDate());
        // fall through branch
        GenericDate descDate = parser.extractLastModifiedDate(text.replace("Published:", ""));
        assertEquals("05-21-2023", descDate.getRawDate());
    }
}
