package filter;

import edu.rit.se.nvip.model.RawVulnerability;

public class SimpleFilter extends Filter {
    @Override
    public boolean passesFilter(RawVulnerability rawVuln) {
        return true;
    }
}
