package edu.rit.se.nvip.reconciler.filter;

import edu.rit.se.nvip.db.model.RawVulnerability;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.*;

/**
 * Extension of the Filter class which implements filterAll() by running the passesFilter() calls in parallel.
 */
public abstract class AsyncFilter extends Filter {

    @Override
    public void filterAll(Set<RawVulnerability> rawVulns) {
        Set<RawVulnerability> rejects = new HashSet<>();
        // set up threads
        ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
        for (RawVulnerability vuln : rawVulns) {
            executor.submit(new FilterTask(vuln));
        }
        try {
            executor.shutdown();
            executor.awaitTermination(rawVulns.size() * 60L, TimeUnit.SECONDS); // wait up to a minute per vuln. todo be smarter about this.
        } catch (InterruptedException ex) {
            logger.error(ex);
        }
    }

    private class FilterTask implements Runnable {
        private final RawVulnerability vuln;
        public FilterTask(RawVulnerability vuln) {
            this.vuln = vuln;
        }

        @Override
        public void run() {
            updateFilterStatus(vuln);
        }
    }

}
