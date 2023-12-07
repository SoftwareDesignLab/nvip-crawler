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

import edu.rit.se.nvip.db.model.RawVulnerability;
import org.junit.Test;

import java.util.List;

import static junit.framework.TestCase.*;

public class DragosParserTest extends AbstractParserTest {

    DragosParser parser = new DragosParser();

    // test a dragos page where there are no CVE IDs available
    @Test
    public void testDragosNA() {
        String html = safeReadHtml("src/test/resources/test-dragos-na.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://www.dragos.com/advisory/yokogawa-centum-vp-dcs-his/",
                html
        );
        assertEquals(0, list.size());
    }

    @Test
    public void testDragosMultiple() {
        String html = safeReadHtml("src/test/resources/test-dragos-mult.html");
        List<RawVulnerability> list = parser.parseWebPage(
                "https://www.dragos.com/advisory/automation-directs-directlogic-06-plc-c-more-ea9-hmi-and-ecom-ethernet-module/",
                html
        );
        assertEquals(4, list.size());
        RawVulnerability vuln = getVulnerability(list, "CVE-2022-2006");
        assertNotNull(vuln);
        assertTrue(vuln.getDescription().contains("Automation Direct’s DirectLogic 06 PLC"));
        assertEquals("2022-05-31 00:00:00", vuln.getPublishDateString());
        assertEquals("2022-05-31 00:00:00", vuln.getLastModifiedDateString());
    }

}
