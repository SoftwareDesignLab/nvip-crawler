package edu.rit.se.nvip.metrics;

import edu.rit.se.nvip.model.RawVulnerability;
import edu.rit.se.nvip.utils.metrics.CrawlerRun;
import edu.rit.se.nvip.utils.metrics.FilterMetrics;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

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

        List<Map<RawVulnerability.SourceType, Integer>> distribution = filterMetrics.sourceTypeDistribution();

        Map<RawVulnerability.SourceType, Integer> otherMap = distribution.get(0);

        assertEquals(3, otherMap.get(RawVulnerability.SourceType.OTHER)); //should be 3 OTHERs


    }


    @Test
    public void numFilteredTest(){
        String path = System.getProperty("user.dir") + "\\src\\test\\resources";

        FilterMetrics filterMetrics = genFilterMetrics(path);

        Map<CrawlerRun, FilterMetrics.FilterStats> filterMap = filterMetrics.numFiltered();

        CrawlerRun run = filterMetrics.getRuns().get(0);


        assertEquals(3, filterMap.get(run).getTotalVulns()); //should have 3 total vulns
        assertEquals(0, filterMap.get(run).getTotalFiltered()); //should have 0 total filtered
    }


    //WAITING FOR UPDATED FILTERS
    @Test
    public void proportionPassedTest(){

        String path = System.getProperty("user.dir") + "\\src\\test\\resources";
        FilterMetrics filterMetrics = genFilterMetrics(path);

        Map<CrawlerRun, Double> propMap = filterMetrics.proportionPassed();

        //assertEquals(0, propMap.get(filterMetrics.getRuns().get(0)));
    }

}