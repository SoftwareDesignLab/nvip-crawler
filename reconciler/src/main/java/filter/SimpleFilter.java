package filter;

import model.RawVulnerability;

public class SimpleFilter extends Filter {
    @Override
    public boolean passesFilter(RawVulnerability rawVuln) {
        return true;
    }
}
