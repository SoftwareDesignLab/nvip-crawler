package edu.rit.se.nvip.filter;

import edu.rit.se.nvip.model.RawVulnerability;
import javafx.util.Pair;

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
        Set<Future<Pair<RawVulnerability, Boolean>>> futures = new HashSet<>();
        for (RawVulnerability vuln : rawVulns) {
            Future<Pair<RawVulnerability, Boolean>> future = executor.submit(new FilterTask(vuln));
            futures.add(future);
        }
        // poll the futures and handle the rejects
        for (Future<Pair<RawVulnerability, Boolean>> future : futures) {
            try {
                Pair<RawVulnerability, Boolean> threadOutput = future.get();
                if (!threadOutput.getValue()) {
                    rawVulns.remove(threadOutput.getKey());
                    rejects.add(threadOutput.getKey());
                }
            } catch (InterruptedException | ExecutionException e) {
                e.printStackTrace();
            }
        }
        executor.shutdown();

        return rejects;
    }

    private class FilterTask implements Callable<Pair<RawVulnerability, Boolean>> {
        private final RawVulnerability vuln;
        public FilterTask(RawVulnerability vuln) {
            this.vuln = vuln;
        }

        @Override
        public Pair<RawVulnerability, Boolean> call() throws Exception {
            boolean result =  passesFilter(vuln);
            return new Pair<>(vuln, result);
        }
    }
}
