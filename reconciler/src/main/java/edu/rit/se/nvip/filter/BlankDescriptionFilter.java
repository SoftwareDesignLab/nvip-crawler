package edu.rit.se.nvip.filter;

import edu.rit.se.nvip.model.RawVulnerability;

/**
 * This class acts as a filter for rawVuln entries where the description is blank
 *
 * @author jqm4954@rit.edu
 */
public class BlankDescriptionFilter extends Filter{
    @Override
    public boolean passesFilter(RawVulnerability rawVuln) {
        return rawVuln.getDescription().equals("") ? false:true;
    }
}
