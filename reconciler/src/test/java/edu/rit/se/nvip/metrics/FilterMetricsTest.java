/**
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
*/

package edu.rit.se.nvip.metrics;

import edu.rit.se.nvip.reconciler.filter.FilterHandler;
import edu.rit.se.nvip.db.model.RawVulnerability;
import edu.rit.se.nvip.utils.metrics.CrawlerRun;
import edu.rit.se.nvip.utils.metrics.FilterMetrics;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class FilterMetricsTest {

    public FilterMetrics genFilterMetrics(String path){
        return new FilterMetrics(path); //generates a new filterMetrics with designated path
    }

    @Nested
    class WithSingleRun {

        final String path = Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString();

        @Test
        public void testFilterMetrics(){
            FilterMetrics filterMetrics = new FilterMetrics(path, new FilterHandler(), FilterHandler.FilterScope.ALL);

            assertEquals(1, filterMetrics.getRuns().size()); //should have 1 run
            assertEquals(3, filterMetrics.getRuns().get(0).getVulns().size()); //should have 3 vulns
        }

        @Test
        public void testNewVulnsPerRun(){
            //tests first file that all vulns added are new
            String path = Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString(); //just 1 json

            FilterMetrics filterMetrics = genFilterMetrics(path);

            Map<CrawlerRun, Integer> newVulns = filterMetrics.newVulnsPerRun();

            assertEquals(3, newVulns.get(filterMetrics.getRuns().get(0)));//should have 3 new vulns
        }

        @Test
        public void testSourceTypeDistribution(){
            FilterMetrics filterMetrics = genFilterMetrics(path);

            Map<CrawlerRun, Map<RawVulnerability.SourceType, Integer>> distribution = filterMetrics.sourceTypeDistribution();

            List<CrawlerRun> runs = filterMetrics.getRuns();

            Map<RawVulnerability.SourceType, Integer> otherMap = distribution.get(runs.get(0));

            assertEquals(3, otherMap.get(RawVulnerability.SourceType.OTHER)); //should be 3 OTHERs
        }

        @Test
        public void testNumFilteredTest(){
            FilterMetrics filterMetrics = genFilterMetrics(path);

            FilterHandler filterHandler = new FilterHandler();
            for (CrawlerRun run : filterMetrics.getRuns()){ //for each run, run filters on the run's vulns
                filterHandler.runFilters(run.getVulns());
            }

            Map<CrawlerRun, FilterMetrics.FilterStats> filterMap = filterMetrics.numFiltered(); //get num filtered

            CrawlerRun run = filterMetrics.getRuns().get(0);

            assertEquals(3, filterMap.get(run).getTotalVulns()); //should have 3 total vulns
            assertEquals(3, filterMap.get(run).getTotalFiltered()); //should have 3 total filtered
            assertEquals(1, filterMap.get(run).getPassedFilters()); //one passes all
            assertEquals(2, filterMap.get(run).getTotalFailed()); //two fail on DescriptionSizeFilter (currently set to < 1000 and the vulns desc are over 1000)
            assertEquals(0, filterMap.get(run).getTotalNotFiltered()); //0 don't get filtered

        }
    }

    @Nested
    class WithMultipleRuns {

        final String path =  Paths.get(System.getProperty("user.dir"), "src", "test", "resources", "multipleJsons").toString(); //2 jsons;

        @Test
        public void testFilterMetrics(){

            FilterMetrics filterMetrics2 = genFilterMetrics(path);

            //test on directory that has multiple json files
            assertEquals(2, filterMetrics2.getRuns().size()); //should have 2 run
            assertEquals(3, filterMetrics2.getRuns().get(0).getVulns().size()); //should have 1 vulns on first run ALL BASED ON VULNID in JSON
            assertEquals(7, filterMetrics2.getRuns().get(1).getVulns().size()); //should have 7 vulns on second run
        }

        @Test
        public void testNewVulnsPerRun(){
            FilterMetrics filterMetrics = genFilterMetrics(path);

            Map<CrawlerRun, Integer> newVulns2 = filterMetrics.newVulnsPerRun();

            assertEquals(3, newVulns2.get(filterMetrics.getRuns().get(0)));//should have 3 new vulns
            assertEquals(4, newVulns2.get(filterMetrics.getRuns().get(1)));//should have 1 new vuln
        }

        @Test
        public void proportionPassedTest(){
            FilterMetrics filterMetrics = genFilterMetrics(path);

            FilterHandler filterHandler = new FilterHandler();
            for (CrawlerRun run : filterMetrics.getRuns()){ //for each run, run filters on the run's vulns
                filterHandler.runFilters(run.getVulns());
            }

            Map<CrawlerRun, Double> propMap = filterMetrics.proportionPassed();

            CrawlerRun run = filterMetrics.getRuns().get(0);
            CrawlerRun run2 = filterMetrics.getRuns().get(1);

            assertEquals(((double) 1 /3), propMap.get(run)); //1 of 3 vulns pass filters
            assertEquals(((double) 4 /7), propMap.get(run2)); //4 of 7 vulns pass filters
        }
    }
}