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

package edu.rit.se.nvip.filter;

import edu.rit.se.nvip.reconciler.filter.FilterHandler;
import edu.rit.se.nvip.reconciler.filter.FilterReturn;
import edu.rit.se.nvip.db.model.RawVulnerability;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class FilterHandlerTest {
    private FilterReturn filterReturnT;
    private FilterReturn filterReturnF;
    @Test
    public void runFiltersTest(){

        FilterHandler filterHandler = new FilterHandler();
        Set<RawVulnerability> rawVulns = new HashSet<>();

        RawVulnerability rawVuln1 = new RawVulnerability(1, "", "1", null, null, null, ""); //this vuln failed CveMatchesDescriptionFilter
        RawVulnerability rawVuln2 = new RawVulnerability(2, "", "desc", null, null, null, "");
        RawVulnerability rawVuln3 = new RawVulnerability(3, "", "description", null, null, null, "");

        rawVulns.add(rawVuln1);
        rawVulns.add(rawVuln2);
        rawVulns.add(rawVuln3);

        List<FilterHandler.FilterScope> list = new ArrayList<>();
        list.add(FilterHandler.FilterScope.LOCAL);
        list.add(FilterHandler.FilterScope.CUSTOM);
        list.add(FilterHandler.FilterScope.REMOTE);
        list.add(FilterHandler.FilterScope.ALL);
        for(FilterHandler.FilterScope scope : list){
            filterReturnT = filterHandler.runFilters(rawVulns, scope, true);
            filterReturnF = filterHandler.runFilters(rawVulns, scope, false);
        }
        // Verify the filter return values
        assertEquals(3, filterReturnT.getNumIn()); //3 went in
        assertEquals(3, filterReturnT.getNumDistinct());
        assertEquals(2, filterReturnT.getNumPassed()); //2 out of 3 pass

    }
}
