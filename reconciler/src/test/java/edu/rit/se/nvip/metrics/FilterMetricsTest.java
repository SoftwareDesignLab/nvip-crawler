package edu.rit.se.nvip.metrics;

import edu.rit.se.nvip.filter.FilterHandler;
import edu.rit.se.nvip.model.RawVulnerability;
import edu.rit.se.nvip.utils.metrics.CrawlerRun;
import edu.rit.se.nvip.utils.metrics.FilterMetrics;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

class FilterMetricsTest {

    public FilterMetrics genFilterMetrics(String path){
        return new FilterMetrics(path); //generates a new filterMetrics with designated path
    }

    @Test
    public void filterMetricsTest(){
        String path = System.getProperty("user.dir") + "\\src\\test\\resources"; //just 1 json
        String path2 = System.getProperty("user.dir") + "\\src\\test\\resources\\multipleJsons"; //2 jsons

        FilterMetrics filterMetrics = genFilterMetrics(path);
        FilterMetrics filterMetrics2 = genFilterMetrics(path2);

        assertEquals(1, filterMetrics.getRuns().size()); //should have 1 run
        assertEquals(3, filterMetrics.getRuns().get(0).getVulns().size()); //should have 3 vulns

        //test on directory that has multiple json files
        assertEquals(2, filterMetrics2.getRuns().size()); //should have 2 run
        assertEquals(3, filterMetrics2.getRuns().get(0).getVulns().size()); //should have 1 vulns on first run ALL BASED ON VULNID in JSON
        assertEquals(7, filterMetrics2.getRuns().get(1).getVulns().size()); //should have 7 vulns on second run


    }

    @Test
    public void newVulnsPerRunTest(){
        //tests first file that all vulns added are new
        String path = System.getProperty("user.dir") + "\\src\\test\\resources";
        String path2 = System.getProperty("user.dir") + "\\src\\test\\resources\\multipleJsons";

        FilterMetrics filterMetrics = genFilterMetrics(path);
        FilterMetrics filterMetrics2 = genFilterMetrics(path2);

        Map<CrawlerRun, Integer> newVulns = filterMetrics.newVulnsPerRun();

        assertEquals(3, newVulns.get(filterMetrics.getRuns().get(0)));//should have 3 new vulns
        //tests that vulns don't repeat

        Map<CrawlerRun, Integer> newVulns2 = filterMetrics2.newVulnsPerRun();

        assertEquals(3, newVulns2.get(filterMetrics2.getRuns().get(0)));//should have 3 new vulns
        assertEquals(4, newVulns2.get(filterMetrics2.getRuns().get(1)));//should have 1 new vuln
    }


    @Test
    public void sourceTypeDistributionTest(){
        String path = System.getProperty("user.dir") + "\\src\\test\\resources";
        FilterMetrics filterMetrics = genFilterMetrics(path);

        Map<CrawlerRun, Map<RawVulnerability.SourceType, Integer>> distribution = filterMetrics.sourceTypeDistribution();

        List<CrawlerRun> runs = filterMetrics.getRuns();

        Map<RawVulnerability.SourceType, Integer> otherMap = distribution.get(runs.get(0));

        assertEquals(3, otherMap.get(RawVulnerability.SourceType.OTHER)); //should be 3 OTHERs


    }


    @Test
    public void numFilteredTest(){
        String path = System.getProperty("user.dir") + "\\src\\test\\resources";

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

    @Test
    public void proportionPassedTest(){

        String path = System.getProperty("user.dir") + "\\src\\test\\resources\\multipleJsons";
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