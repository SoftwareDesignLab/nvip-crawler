package edu.rit.se.nvip.filter;

import edu.rit.se.nvip.model.RawVulnerability;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.*;

/**
 * Extension of the Filter class which implements filterAll() by running the passesFilter() calls in parallel.
 */
public abstract class AsyncFilter extends Filter {

    @Override
    public Set<RawVulnerability> filterAll(Set<RawVulnerability> rawVulns) {
        Set<RawVulnerability> rejects = new HashSet<>();
        // set up threads
        ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
        Set<Future<FilterTaskReturn>> futures = new HashSet<>();
        for (RawVulnerability vuln : rawVulns) {
            Future<FilterTaskReturn> future = executor.submit(new FilterTask(vuln));
            futures.add(future);
        }
        // poll the futures and handle the rejects
        for (Future<FilterTaskReturn> future : futures) {
            try {
                FilterTaskReturn threadOutput = future.get();
                if (!threadOutput.passes) {
                    rawVulns.remove(threadOutput.vulnInput);
                    rejects.add(threadOutput.vulnInput);
                }
            } catch (InterruptedException | ExecutionException e) {
                logger.error("Error while polling future");
                logger.error(e);
            }
        }
        executor.shutdown();
        return rejects;
    }

    private class FilterTask implements Callable<FilterTaskReturn> {
        private final RawVulnerability vuln;
        public FilterTask(RawVulnerability vuln) {
            this.vuln = vuln;
        }

        @Override
        public FilterTaskReturn call() {
            // respect API rate limits!
            waitForLimiters(vuln);
            return new FilterTaskReturn(vuln, passesFilter(vuln));
        }
    }

    private static class FilterTaskReturn {
        public RawVulnerability vulnInput;
        public boolean passes;
        FilterTaskReturn(RawVulnerability vulnInput, boolean passes) {
            this.vulnInput = vulnInput;
            this.passes = passes;
        }
    }

    protected void waitForLimiters(RawVulnerability vuln) {
        return;
    }
}
