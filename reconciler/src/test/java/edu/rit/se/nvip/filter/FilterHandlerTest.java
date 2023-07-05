package edu.rit.se.nvip.filter;

import edu.rit.se.nvip.model.RawVulnerability;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class FilterHandlerTest {
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

        FilterReturn filterReturn = filterHandler.runFilters(rawVulns);

        // Verify the filter return values
        assertEquals(3, filterReturn.getNumIn()); //3 went in
        assertEquals(3, filterReturn.getNumDistinct());
        assertEquals(2, filterReturn.getNumPassed()); //2 out of 3 pass


    }
}
