package edu.rit.se.nvip.filter;

import edu.rit.se.nvip.model.RawVulnerability;
import edu.rit.se.nvip.openai.GPTFilterModel;

public class GPTFilter extends AsyncFilter {
    private GPTFilterModel model = new GPTFilterModel();
    private static long tokenTotal = 0;
    private static int processed = 0;
    private static int irregular = 0;
    private static int rejected = 0;

    public GPTFilter() {
        this.model = new GPTFilterModel();
    }

    public void setModel(GPTFilterModel model) {
        this.model = model;
    }

    @Override
    public boolean passesFilter(RawVulnerability vuln) {
        int tokens = model.tokenCount(vuln.getDescription());
        processed += 1;
        if (tokens > 4097) {
            logger.warn("{} from {} with id {} uses too many ({}) tokens for an OpenAI request. REJECTING", vuln.getCveId(), vuln.getSourceUrl(), vuln.getId(), tokens);
            return false;
        }
        boolean response;
        try {
            response = model.callModel(vuln.getDescription());
        } catch (GPTFilterModel.OpenAiInvalidReturnException e) {
            response = true; // most vulns are ok, so in the event of error we let it pass
            irregular += 1;
        }
        tokenTotal += tokens;
        if (processed % 10 == 0) {
            logger.info("{} vulns filtered so far and {}k tokens have been used so far with {} rejects and {} irregularities", processed, tokenTotal/1000, rejected, irregular);
        }
        if (!response) {
            logger.info("{} from {} with id {} REJECTED by OpenAi", vuln.getCveId(), vuln.getSourceUrl(), vuln.getId());
            rejected += 1;
        }
        return response;
    }
}
