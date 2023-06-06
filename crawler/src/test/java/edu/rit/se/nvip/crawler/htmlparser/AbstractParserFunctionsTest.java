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
