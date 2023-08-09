/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package edu.rit.se.nvip.sandbox;

import edu.rit.se.nvip.filter.Filter;
import edu.rit.se.nvip.filter.FilterFactory;
import edu.rit.se.nvip.filter.FilterHandler;
import edu.rit.se.nvip.model.RawVulnerability;
import edu.rit.se.nvip.utils.metrics.CrawlerRun;
import edu.rit.se.nvip.utils.metrics.FilterMetrics;

import javax.json.*;
import java.io.FileWriter;
import java.io.IOException;
import java.text.DecimalFormat;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * This class acts as a tool for identifying filter metrics at various levels.
 */
public class FilterMetricsOutputTool {
    private FilterMetrics currentFilterMetrics;
    private Map<CrawlerRun, Map<RawVulnerability.SourceType, Integer>> sourceDist;
    private Map<CrawlerRun, FilterMetrics.FilterStats> numFiltered;
    private Map<CrawlerRun, Double> proportionPassed;
    private Map<CrawlerRun, Integer> newVulnsPerRun;
    private static final DecimalFormat df = new DecimalFormat("0.00");
    private static final DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy_MM_dd HH_mm_ss");

    public FilterMetricsOutputTool(FilterMetrics filterMetrics) {
        this.currentFilterMetrics = filterMetrics;
        this.sourceDist = filterMetrics.sourceTypeDistribution();
        this.numFiltered = filterMetrics.numFiltered();
        this.proportionPassed = filterMetrics.proportionPassed();
        this.newVulnsPerRun = filterMetrics.newVulnsPerRun();

    }

    /**
     * Given the objects current metrics, create a JsonObject containing all metrics for each crawler run
     * @return a JsonObject containing filter metrics for every CrawlerRun in the current filterMetrics object
     */
    public JsonObject buildAllMetrics() {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("Total Crawler Runs", currentFilterMetrics.getRuns().size());
        JsonObjectBuilder filters = Json.createObjectBuilder();
        int totalVulns = 0;
        int totalFiltered = 0;
        int totalPassed = 0;
        int filterIndex = 0;
        for (Filter currentFilter: currentFilterMetrics.getFilterHandler().getCustomFilters()) {
            filters.add(filterIndex+"", currentFilter.getClass().getSimpleName());
            filterIndex++;
        }
        builder.add("Filters", filters);
        for (CrawlerRun currentRun: currentFilterMetrics.getRuns()) {
            //Add to JsonObject for every CrawlerRun and it's metrics
            JsonObjectBuilder joRun = Json.createObjectBuilder();

            joRun.add("Crawled Date", currentRun.getDate().toString());

            joRun.add("Vulns", numFiltered.get(currentRun).getTotalVulns());
            totalVulns += numFiltered.get(currentRun).getTotalVulns();

            joRun.add("Vulns Filtered", numFiltered.get(currentRun).getTotalFiltered());
            totalFiltered += numFiltered.get(currentRun).getTotalFiltered();

            joRun.add("Vulns Pass Filters", numFiltered.get(currentRun).getPassedFilters());
            totalPassed += numFiltered.get(currentRun).getPassedFilters();

            joRun.add("Proportion Passed", df.format(proportionPassed.get(currentRun)));

            joRun.add("New Vulns", newVulnsPerRun.get(currentRun));

            Map<RawVulnerability.SourceType, Integer> sourceMap = sourceDist.get(currentRun);
            JsonObjectBuilder joSource = Json.createObjectBuilder();
            for (RawVulnerability.SourceType currentSource: sourceMap.keySet()) {
                joSource.add(currentSource.getType(), sourceMap.get(currentSource));
            }
            joRun.add("Source Distribution", joSource);

            builder.add("Run " + currentRun.getRunId(), joRun);
        }
        //Add metrics between all crawler runs to end of the JsonObject
        builder.add("Total Vulns", totalVulns);
        builder.add("Total Vulns Filtered", totalFiltered);
        builder.add("Total Vulns Pass Filters", totalPassed);
        return builder.build();
    }

    /**
     * Updates the current metrics given a new filter metrics object
     * @param filterMetrics FilterMetrics object containing new metrics to update output with
     */
    public void updateCurrentFilterMetrics(FilterMetrics filterMetrics) {
        this.currentFilterMetrics = filterMetrics;
        this.sourceDist = filterMetrics.sourceTypeDistribution();
        this.numFiltered = filterMetrics.numFiltered();
        this.proportionPassed = filterMetrics.proportionPassed();
        this.newVulnsPerRun = filterMetrics.newVulnsPerRun();
    }

    /**
     * Builds a JsonObject of filter metrics given a single filter type
     * @param filter type of filter to run on given crawler runs
     * @param currentMetrics FilterMetrics object that is used to update the metrics run on a crawler run set
     * @return
     */
    public JsonObject buildSingleFilterMetrics(String filter, FilterMetrics currentMetrics) {
        List<Filter> customFilter = new ArrayList<>();
        customFilter.add(FilterFactory.createFilter(filter));
        currentMetrics.setCustomFilters(customFilter);
        updateCurrentFilterMetrics(currentMetrics);
        return buildAllMetrics();
    }

    /**
     * Creates a json array of filter metrics with all local filters, and individual filters.
     * Points to specific directory and finds crawler runs to create metrics on.
     */
    public static void main(String[] args) {
        //Create the list of all local filters to be used for metrics
        List<Filter> customFilters = new ArrayList<>();
        customFilters.add(FilterFactory.createFilter(FilterFactory.MULTIPLE_CVE_DESCRIPTION));
        customFilters.add(FilterFactory.createFilter(FilterFactory.CVE_MATCHES_DESCRIPTION));
        customFilters.add(FilterFactory.createFilter(FilterFactory.DESCRIPTION_SIZE));
        customFilters.add(FilterFactory.createFilter(FilterFactory.INTEGER_DESCRIPTION));
        customFilters.add(FilterFactory.createFilter(FilterFactory.BLANK_DESCRIPTION));
        customFilters.add(FilterFactory.createFilter(FilterFactory.CHARACTER_PROPORTION));
        customFilters.add(FilterFactory.createFilter(FilterFactory.JSON_DESCRIPTION));

        FilterHandler filterHandler = new FilterHandler();
        filterHandler.setCustomFilters(customFilters);
        //Creates a FilterMetrics object based on the CrawlerRuns in the given directory
        FilterMetrics filterMetrics = new FilterMetrics("./src/test/resources", filterHandler, FilterHandler.FilterScope.CUSTOM);
        FilterMetricsOutputTool fmot = new FilterMetricsOutputTool(filterMetrics);

        JsonObjectBuilder objBuilder = Json.createObjectBuilder();

        //Build object with all local filters
        objBuilder.add("LOCAL_FILTERS", fmot.buildAllMetrics());


        //Build object with MULTIPLE_CVE_DESCRIPTION filter
        objBuilder.add("MULTIPLE_CVE_DESCRIPTION", fmot.buildSingleFilterMetrics(FilterFactory.MULTIPLE_CVE_DESCRIPTION, filterMetrics));
        //Build object with CVE_MATCHES_DESCRIPTION filter
        objBuilder.add("CVE_MATCHES_DESCRIPTION", fmot.buildSingleFilterMetrics(FilterFactory.CVE_MATCHES_DESCRIPTION, filterMetrics));
        //Build object with DESCRIPTION_SIZE filter
        objBuilder.add("DESCRIPTION_SIZE", fmot.buildSingleFilterMetrics(FilterFactory.DESCRIPTION_SIZE, filterMetrics));
        //Build object with INTEGER_DESCRIPTION filter
        objBuilder.add("INTEGER_DESCRIPTION", fmot.buildSingleFilterMetrics(FilterFactory.INTEGER_DESCRIPTION, filterMetrics));
        //Build object with BLANK_DESCRIPTION filter
        objBuilder.add("BLANK_DESCRIPTION", fmot.buildSingleFilterMetrics(FilterFactory.BLANK_DESCRIPTION, filterMetrics));
        //Build object with CHARACTER_PROPORTION filter
        objBuilder.add("CHARACTER_PROPORTION", fmot.buildSingleFilterMetrics(FilterFactory.CHARACTER_PROPORTION, filterMetrics));
        //Build object with JSON_DESCRIPTION filter
        objBuilder.add("JSON_DESCRIPTION", fmot.buildSingleFilterMetrics(FilterFactory.JSON_DESCRIPTION, filterMetrics));


        JsonObject obj = objBuilder.build();

        LocalDateTime now = LocalDateTime.now();
        try (FileWriter writer = new FileWriter("./src/main/java/edu/rit/se/nvip/sandbox/jsons/FilterMetricsOutput_" + dtf.format(now) + ".json")) {
            writer.write(obj.toString());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
