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

    public String getAllMetricsString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Total Runs," + currentFilterMetrics.getRuns().size() + "\n");
        sb.append("Filters Used,");
        for (Filter currentFilter: currentFilterMetrics.getFilterHandler().getCustomFilters()) {
            sb.append(currentFilter.getClass().getSimpleName() + ",");
        }
        sb.replace(sb.length()-1, sb.length(), "\n");
        int sourceIndex = 0;
        for (Map<RawVulnerability.SourceType, Integer> currentRun: sourceDist.values()) {
            sb.append("Current Run," + sourceIndex + "\n");
            sourceIndex++;
            for (RawVulnerability.SourceType currentSource: currentRun.keySet()) {
                sb.append("Current Source," + currentSource + ",Count," + currentRun.get(currentSource) +",");
            }
            sb.append("\n");
        }
        sb.append("\n");
        for (CrawlerRun currentRun: numFiltered.keySet()) {
            sb.append("Current Run Date," + currentRun.getDate() +
                    "\nNumTotalFiltered," + numFiltered.get(currentRun).getTotalFiltered() +
                    ",NumPassedFilters," + numFiltered.get(currentRun).getPassedFilters() +
                    ",Proportion Passed," + df.format(proportionPassed.get(currentRun)) + "\n");
        }
        return sb.toString();
    }

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
        builder.add("Total Vulns", totalVulns);
        builder.add("Total Vulns Filtered", totalFiltered);
        builder.add("Total Vulns Pass Filters", totalPassed);
        return builder.build();
    }

    public void updateCurrentFilterMetrics(FilterMetrics filterMetrics) {
        this.currentFilterMetrics = filterMetrics;
        this.sourceDist = filterMetrics.sourceTypeDistribution();
        this.numFiltered = filterMetrics.numFiltered();
        this.proportionPassed = filterMetrics.proportionPassed();
        this.newVulnsPerRun = filterMetrics.newVulnsPerRun();
    }

    public JsonObject buildSingleFilterMetrics(String filter, FilterMetrics currentMetrics) {
        List<Filter> customFilter = new ArrayList<>();
        customFilter.add(FilterFactory.createFilter(filter));
        currentMetrics.setCustomFilters(customFilter);
        updateCurrentFilterMetrics(currentMetrics);
        return buildAllMetrics();
    }

    public static void main(String[] args) {
        List<Filter> customFilters = new ArrayList<>();
        customFilters.add(FilterFactory.createFilter(FilterFactory.MULTIPLE_CVE_DESCRIPTION));
        customFilters.add(FilterFactory.createFilter(FilterFactory.CVE_MATCHES_DESCRIPTION));
        customFilters.add(FilterFactory.createFilter(FilterFactory.DESCRIPTION_SIZE));
        customFilters.add(FilterFactory.createFilter(FilterFactory.INTEGER_DESCRIPTION));
        customFilters.add(FilterFactory.createFilter(FilterFactory.BLANK_DESCRIPTION));

        FilterHandler filterHandler = new FilterHandler();
        filterHandler.setCustomFilters(customFilters);
        FilterMetrics filterMetrics = new FilterMetrics("./src/test/resources/multipleJsons", filterHandler, FilterHandler.FilterScope.CUSTOM);
        FilterMetricsOutputTool fmot = new FilterMetricsOutputTool(filterMetrics);

        JsonObjectBuilder objBuilder = Json.createObjectBuilder();

        //Build object with all local filters
        objBuilder.add("LOCAL_FILTERS", fmot.buildAllMetrics());

        //Build object with MULTIPLE_CVE_DESCRIPTION filter
        objBuilder.add("MULTIPLE_CVE_DESCRIPTION", fmot.buildSingleFilterMetrics(FilterFactory.MULTIPLE_CVE_DESCRIPTION, filterMetrics));
        //Build object with CVE_MATCHES_DESCRIPTION filter
        objBuilder.add("CVE_MATCHES_DESCRIPTION", fmot.buildSingleFilterMetrics(FilterFactory.CVE_MATCHES_DESCRIPTION, filterMetrics));
        //Build object with CVE_MATCHES_DESCRIPTION filter
        objBuilder.add("DESCRIPTION_SIZE", fmot.buildSingleFilterMetrics(FilterFactory.DESCRIPTION_SIZE, filterMetrics));
        //Build object with CVE_MATCHES_DESCRIPTION filter
        objBuilder.add("INTEGER_DESCRIPTION", fmot.buildSingleFilterMetrics(FilterFactory.INTEGER_DESCRIPTION, filterMetrics));
        //Build object with CVE_MATCHES_DESCRIPTION filter
        objBuilder.add("BLANK_DESCRIPTION", fmot.buildSingleFilterMetrics(FilterFactory.BLANK_DESCRIPTION, filterMetrics));

        JsonObject obj = objBuilder.build();

        LocalDateTime now = LocalDateTime.now();
        try (FileWriter writer = new FileWriter("./src/main/java/edu/rit/se/nvip/sandbox/jsons/FilterMetricsOutput_" + dtf.format(now) + ".json")) {
            writer.write(obj.toString());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
