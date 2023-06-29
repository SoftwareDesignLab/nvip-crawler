package edu.rit.se.nvip.metrics;

import edu.rit.se.nvip.utils.metrics.CrawlerRun;
import edu.rit.se.nvip.utils.metrics.FilterMetrics;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class FilterMetricsTest {

    @Test
    public void filterMetricsTest(){
        String path = System.getProperty("user.dir") + "\\src\\test\\resources";

        FilterMetrics filterMetrics = new FilterMetrics(path);

        assertEquals(1, filterMetrics.getRuns().size());
        assertEquals(3, filterMetrics.getRuns().get(0).getVulns().size());

        //test on directory that has multiple json files

        String path2 = System.getProperty("user.dir") + "\\src\\test\\resources\\multipleJsons";

        FilterMetrics filterMetrics2 = new FilterMetrics(path2);

        System.out.println(filterMetrics2);
        assertEquals(2, filterMetrics2.getRuns().size());
        assertEquals(3, filterMetrics2.getRuns().get(0).getVulns().size());
        assertEquals(3, filterMetrics2.getRuns().get(1).getVulns().size());


    }
    @Test
    public void newVulnsPerRunTest(){
        //tests first file that all vulns added are new
        String path = System.getProperty("user.dir") + "\\src\\test\\resources";

        FilterMetrics filterMetrics = new FilterMetrics(path);

        Map<CrawlerRun, Integer> newVulns = filterMetrics.newVulnsPerRun();


        assertEquals(3, newVulns.get(filterMetrics.getRuns().get(0)));

        //tests that vulns don't repeat
        String path2 = System.getProperty("user.dir") + "\\src\\test\\resources\\multipleJsons";

        FilterMetrics filterMetrics2 = new FilterMetrics(path2);

        Map<CrawlerRun, Integer> newVulns2 = filterMetrics2.newVulnsPerRun();

        assertEquals(3, newVulns2.get(filterMetrics2.getRuns().get(0)));
        assertEquals(1, newVulns2.get(filterMetrics2.getRuns().get(1)));
    }

    @Test
    public void sourceTypeDistributionTest(){

    }

    @Test
    public void numFilteredTest(){

    }

    @Test
    public void proportionPassedTest(){

    }

}