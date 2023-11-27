package edu.rit.se.nvip.filter;

import edu.rit.se.nvip.db.model.RawVulnerability;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class AsyncFilterTest {
    private RawVulnerability genRawVuln(int id) {
        return new RawVulnerability(id, "", "description"+id, null, null, null, "" );
    }
    //verifies that you can filter using the async filter
    @Test
    void filterAllTest() {
        Set<RawVulnerability> rawVulns = new HashSet<>();
        int count = 5;
        while(count > 0 ){
            rawVulns.add(genRawVuln(count));
            count--;
        }

        AsyncFilter filter = new AsyncFilter() {
            @Override
            public boolean passesFilter(RawVulnerability rawVuln) {
                SimpleFilter simpleFilter = new SimpleFilter();
                return simpleFilter.passesFilter(rawVuln);
            }
        };

        filter.filterAll(rawVulns);

        assertEquals(5, rawVulns.size());
    }
}