package edu.rit.se.nvip.filter;

import edu.rit.se.nvip.db.model.RawVulnerability;

/**
 * This class acts as a filter for rawVuln entries where the description is blank
 *
 * @author jqm4954@rit.edu
 */
public class BlankDescriptionFilter extends Filter{
    @Override
    public boolean passesFilter(RawVulnerability rawVuln) {
        String description = rawVuln.getDescription();
        description = description.trim();
        return !description.equals("");
    }
}
