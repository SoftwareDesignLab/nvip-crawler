package edu.rit.se.nvip.filter;

import edu.rit.se.nvip.model.RawVulnerability;
import edu.rit.se.nvip.reconciler.filter.FilterHandler;
import edu.rit.se.nvip.reconciler.filter.FilterReturn;
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
