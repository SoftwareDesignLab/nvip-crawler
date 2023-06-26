package edu.rit.se.nvip.filter;

import com.google.common.util.concurrent.RateLimiter;
import edu.rit.se.nvip.model.RawVulnerability;
import edu.rit.se.nvip.sandbox.DatabaseSandbox;

import java.util.HashSet;
import java.util.Set;

public class GPTFilter extends AsyncFilter {
    private GPTFilterModel model = new GPTFilterModel();

    //https://platform.openai.com/account/rate-limits
    private static final double TOKEN_RATE_LIMIT = 90000. / 60;
    private static final double REQUEST_RATE_LIMIT = 3500. / 60;
    private static final RateLimiter tokenLimiter = RateLimiter.create(TOKEN_RATE_LIMIT);
    private static final RateLimiter requestLimiter = RateLimiter.create(REQUEST_RATE_LIMIT);
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

    @Override
    protected void waitForLimiters(RawVulnerability vuln) {
        tokenLimiter.acquire(model.tokenCount(vuln.getDescription()));
        requestLimiter.acquire(1);
    }
}
