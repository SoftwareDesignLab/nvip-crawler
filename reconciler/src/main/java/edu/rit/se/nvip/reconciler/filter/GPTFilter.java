/ **
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
* /

package edu.rit.se.nvip.reconciler.filter;

import edu.rit.se.nvip.reconciler.openai.GPTFilterModel;
import edu.rit.se.nvip.db.model.RawVulnerability;

public class GPTFilter extends AsyncFilter {
    private GPTFilterModel model;
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
            // todo should this be handled inside the GPTFilterModel class instead?
            //logger.warn("{} from {} with id {} uses too many ({}) tokens for an OpenAI request. REJECTING", vuln.getCveId(), vuln.getSourceUrl(), vuln.getId(), tokens);
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
            //logger.info("{} vulns filtered so far and {}k tokens have been used so far with {} rejects and {} irregularities", processed, tokenTotal/1000, rejected, irregular);
        }
        if (!response) {
            //logger.info("{} from {} with id {} REJECTED by OpenAi", vuln.getCveId(), vuln.getSourceUrl(), vuln.getId());
            rejected += 1;
        }
        return response;
    }
}
