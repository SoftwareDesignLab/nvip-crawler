package edu.rit.se.nvip.sandbox;

import edu.rit.se.nvip.filter.Filter;
import edu.rit.se.nvip.filter.FilterFactory;
import edu.rit.se.nvip.filter.FilterStatus;
import edu.rit.se.nvip.filter.GPTFilter;
import edu.rit.se.nvip.model.RawVulnerability;
import edu.rit.se.nvip.model.VulnSetWrapper;
import edu.rit.se.nvip.openai.OpenAIRequestHandler;

import javax.json.*;
import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

public class DatasetHandler {
    String jsonPathRaw = "./src/main/java/edu/rit/se/nvip/sandbox/filter_dataset.json";

    String jsonPathLabeled = "./src/main/java/edu/rit/se/nvip/sandbox/filter_dataset_labeled.json";

    DatabaseSandbox db;
    public static void main(String[] args) {
        DatasetHandler dh = new DatasetHandler();
        dh.runGPT("./src/main/java/edu/rit/se/nvip/sandbox/jsons/CrawlerOutputFull_6_22_2023.json", true);
        OpenAIRequestHandler rh = OpenAIRequestHandler.getInstance();
        rh.shutdown();
    }

    public DatasetHandler() {
        db = DatabaseSandbox.getInstance("jdbc:mysql://localhost:3306/nviptest?useSSL=false&allowPublicKeyRetrieval=true",
                "root",
                "password");
    }
    public void jsonToDb(String jsonPath) {
        JsonArray jVulns = null;
        try (FileReader reader = new FileReader(jsonPath)) {
            JsonReader jReader = Json.createReader(reader);
            jVulns = jReader.readArray();
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (jVulns == null) {
            return;
        }
        LinkedHashMap<RawVulnerability, Integer> vulns = new LinkedHashMap<>();
        for (int i = 0; i < jVulns.size(); i++) {
            JsonObject jo = jVulns.getJsonObject(i);
            vulns.put(new RawVulnerability(
                    jo.getInt("raw_description_id"),
                    jo.getString("cve_id"),
                    jo.getString("raw_description"),
                    new Timestamp(jo.getJsonNumber("published_date").longValue()),
                    new Timestamp(jo.getJsonNumber("last_modified_date").longValue()),
                    new Timestamp(jo.getJsonNumber("created_date").longValue()),
                    jo.getString("source_url")
            ), jo.getInt("is_garbage"));
        }
        db.clearAndInsertFilterDataset(vulns);
    }

    public void dbToJson(String jsonPath) {
        LinkedHashMap<RawVulnerability, Integer> vulnMap = db.getFilterDataset();
        JsonArrayBuilder builder = Json.createArrayBuilder();
        for (RawVulnerability vuln : vulnMap.keySet()) {
            JsonObjectBuilder ob = Json.createObjectBuilder();
            ob.add("raw_description_id", vuln.getId());
            ob.add("raw_description", vuln.getDescription());
            ob.add("cve_id", vuln.getCveId());
            ob.add("created_date", vuln.getCreateDate().getTime());
            ob.add("published_date", vuln.getPublishDate().getTime());
            ob.add("last_modified_date", vuln.getLastModifiedDate().getTime());
            ob.add("source_url", vuln.getSourceUrl());
            ob.add("source_type", vuln.getSourceType().getType());
            ob.add("filter_status", vuln.getFilterStatus().value);
            builder.add(ob);
        }
        JsonArray ja = builder.build();

        try (FileWriter writer = new FileWriter(jsonPath)) {
            writer.write(ja.toString());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Runs local filters on json file containing entries from rawdescription table
     * @param jsonPath The path to a json file with entries from the rawdescription table
     */
    public void runLocalFiltersOnData(String jsonPath) {
        List<Filter> filters = new ArrayList<>();
        filters.add(FilterFactory.createFilter(FilterFactory.MULTIPLE_CVE_DESCRIPTION));
        filters.add(FilterFactory.createFilter(FilterFactory.BLANK_DESCRIPTION));
        filters.add(FilterFactory.createFilter(FilterFactory.INTEGER_DESCRIPTION));
        filters.add(FilterFactory.createFilter(FilterFactory.DESCRIPTION_SIZE));
        filters.add(FilterFactory.createFilter(FilterFactory.CVE_MATCHES_DESCRIPTION));

        JsonArray jArray = null;
        try (FileReader reader = new FileReader(jsonPath)) {
            JsonReader jReader = Json.createReader(reader);
            jArray = jReader.readArray();
        } catch (IOException e) {
            e.printStackTrace();
        }
        Set<RawVulnerability> rawVulns = new HashSet<>();
        for (int i = 0; i < jArray.size(); i++) {
            JsonObject jo = jArray.getJsonObject(i);
            rawVulns.add(new RawVulnerability(
                    jo.getInt("raw_description_id"),
                    jo.getString("cve_id"),
                    jo.getString("raw_description"),
                    new Timestamp(jo.getJsonNumber("published_date").longValue()),
                    new Timestamp(jo.getJsonNumber("last_modified_date").longValue()),
                    new Timestamp(jo.getJsonNumber("created_date").longValue()),
                    jo.getString("source_url"),
                    jo.getString("source_type"),
                    jo.getInt("filter_status")));
        }
        Set<RawVulnerability> rejected = new HashSet<>();
        Set<RawVulnerability> unFiltered = rawVulns;
        for (Filter filter: filters) {
//            Set<RawVulnerability> currentRejected = filter.filterAllAndSplit(unFiltered); // todo filter technique
//            rejected.addAll(currentRejected);
//            unFiltered.removeAll(currentRejected);
        }

        System.out.println("Total: " + jArray.size());
        System.out.println("Rejected Count: " + rejected.size());
        System.out.println("Accepted Count: " + unFiltered.size());
    }

    public void runGPT(String jsonPath, boolean removeLocalFiltered) {
        List<Filter> filters = new ArrayList<>();
        filters.add(FilterFactory.createFilter(FilterFactory.MULTIPLE_CVE_DESCRIPTION));
        filters.add(FilterFactory.createFilter(FilterFactory.BLANK_DESCRIPTION));
        filters.add(FilterFactory.createFilter(FilterFactory.INTEGER_DESCRIPTION));
        filters.add(FilterFactory.createFilter(FilterFactory.DESCRIPTION_SIZE));
        filters.add(FilterFactory.createFilter(FilterFactory.CVE_MATCHES_DESCRIPTION));

        JsonArray jArray = null;
        try (FileReader reader = new FileReader(jsonPath)) {
            JsonReader jReader = Json.createReader(reader);
            jArray = jReader.readArray();
        } catch (IOException e) {
            e.printStackTrace();
        }
        Set<RawVulnerability> rawVulns = new HashSet<>();
        for (int i = 0; i < jArray.size(); i++) {
            JsonObject jo = jArray.getJsonObject(i);
            rawVulns.add(new RawVulnerability(
                    jo.getInt("raw_description_id"),
                    jo.getString("cve_id"),
                    jo.getString("raw_description"),
                    new Timestamp(jo.getJsonNumber("published_date").longValue()),
                    new Timestamp(jo.getJsonNumber("last_modified_date").longValue()),
                    new Timestamp(jo.getJsonNumber("created_date").longValue()),
                    jo.getString("source_url"),
                    jo.getString("source_type"),
                    jo.getInt("filter_status")));
        }
        System.out.println("Parsed rawvulns: " + rawVulns.size());
        Set<RawVulnerability> unFiltered = rawVulns;
        if (removeLocalFiltered) {
            Set<RawVulnerability> currentRejected;
            for (Filter filter: filters) {
                //currentRejected = filter.filterAllAndSplit(unFiltered); // todo filter technique
                //unFiltered.removeAll(currentRejected);
            }
        }

        GPTFilter gptFilter = new GPTFilter();

        int indexMax = 100;
        Set<RawVulnerability> filterSet = new HashSet<>();
        for (int i = 0; i < indexMax; i ++) {
            filterSet.add((RawVulnerability) unFiltered.toArray()[i]);
        }

        int remoteTotalCount = filterSet.size();
        Set<RawVulnerability> rejected = new HashSet<>();

        System.out.println("Total for GPT filter: " + remoteTotalCount);
        //rejected.addAll(gptFilter.filterAllAndSplit(filterSet)); // todo filter technique

        System.out.println("Total: " + remoteTotalCount);
        System.out.println("Rejected: " + rejected.size());
        createJsonFromSet(filterSet, false);
        createJsonFromSet(rejected, true);
    }

    private void createJsonFromSet(Set<RawVulnerability> rawVulns, boolean isRejected) {
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy_MM_dd HH_mm_ss");
        LocalDateTime now = LocalDateTime.now();
        JsonArrayBuilder jsonArrayBuilder = Json.createArrayBuilder();
        for (RawVulnerability currentVuln: rawVulns) {
            JsonObjectBuilder vulnBuilder = Json.createObjectBuilder();
            vulnBuilder.add("raw_description_id", currentVuln.getId());
            vulnBuilder.add("cve_id", currentVuln.getCveId());
            vulnBuilder.add("raw_description", currentVuln.getDescription());
            vulnBuilder.add("filter_status", currentVuln.getFilterStatus().value);
            jsonArrayBuilder.add(vulnBuilder);
        }

        JsonArray ja = jsonArrayBuilder.build();

        String jsonPath = "./src/main/java/edu/rit/se/nvip/sandbox/jsons/GPTFilteredVulns";
        if (isRejected) {
            jsonPath += "Failed";
        } else {
            jsonPath += "Passed";
        }
        jsonPath += "_" + dtf.format(now) + ".json";

        try (FileWriter writer = new FileWriter(jsonPath)) {
            writer.write(ja.toString());
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public void updateJson(String jsonPath) {
        //Pull source type and put in map, follows (domain, type) K/V
        LinkedHashMap<String, String> sourceTypes = new LinkedHashMap<>();
        try {
            File reader = new File("./../crawler/resources/url-sources/nvip-source-types.txt");
            Scanner scan = new Scanner(reader);
            while (scan.hasNextLine()) {
                String currentLine = scan.nextLine();
                String[] args = currentLine.split(" ");
                try {
                    sourceTypes.put(args[0].replaceAll("www.", ""), args[1]);
                } catch (ArrayIndexOutOfBoundsException e) {
                    sourceTypes.put(args[0].replaceAll("www.", ""), "other");
                }
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return;
        }

        JsonArray jArray = null;
        try (FileReader reader = new FileReader(jsonPath)) {
            JsonReader jReader = Json.createReader(reader);
            jArray = jReader.readArray();
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }

        JsonArrayBuilder builder = Json.createArrayBuilder();

        String currentSource;
        for (int i = 0; i < jArray.size(); i++) {
            JsonObject jo = jArray.getJsonObject(i);
            String host = "";
            try {
                URI url = new URI(jo.getString("source_url"));
                host = url.getHost();
            } catch (URISyntaxException e) {
                e.printStackTrace();
            }
            currentSource = host.replaceAll("www.", "");
            String currentSourceType = sourceTypes.get(currentSource);
            if (currentSourceType == null) {
                currentSourceType = "other";
            }
            JsonObjectBuilder ob = Json.createObjectBuilder();
            ob.add("raw_description_id", jo.getInt("raw_description_id"));
            ob.add("raw_description", jo.getString("raw_description"));
            ob.add("cve_id", jo.getString("cve_id"));
            ob.add("created_date", jo.getJsonNumber("created_date").longValue());
            ob.add("published_date", jo.getJsonNumber("published_date").longValue());
            ob.add("last_modified_date", jo.getJsonNumber("last_modified_date").longValue());
            ob.add("source_url", jo.getString("source_url"));
            ob.add("source_type", currentSourceType);
            ob.add("filter_status", 1);
            builder.add(ob);
        }
        JsonArray ja = builder.build();

        try (FileWriter writer = new FileWriter("./src/main/java/edu/rit/se/nvip/sandbox/CrawlerOutputFull_6_22_2023.json")) {
            writer.write(ja.toString());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void firstSecondWaveFilterMetrics(String jsonPath) {
        JsonArray jArray = null;
        try (FileReader reader = new FileReader(jsonPath)) {
            JsonReader jReader = Json.createReader(reader);
            jArray = jReader.readArray();
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }
        Set<RawVulnerability> rawVulns = new HashSet<>();
        for (int i = 0; i < jArray.size(); i++) {
            JsonObject jo = jArray.getJsonObject(i);
            rawVulns.add(new RawVulnerability(
                    jo.getInt("raw_description_id"),
                    jo.getString("cve_id"),
                    jo.getString("raw_description"),
                    new Timestamp(jo.getJsonNumber("published_date").longValue()),
                    new Timestamp(jo.getJsonNumber("last_modified_date").longValue()),
                    new Timestamp(jo.getJsonNumber("created_date").longValue()),
                    jo.getString("source_url"),
                    jo.getString("source_type"),
                    jo.getInt("filter_status")));
        }

        Set<Filter> filters = new HashSet<>();
        filters.add(FilterFactory.createFilter(FilterFactory.MULTIPLE_CVE_DESCRIPTION));
        filters.add(FilterFactory.createFilter(FilterFactory.BLANK_DESCRIPTION));
        filters.add(FilterFactory.createFilter(FilterFactory.INTEGER_DESCRIPTION));
        filters.add(FilterFactory.createFilter(FilterFactory.DESCRIPTION_SIZE));
        filters.add(FilterFactory.createFilter(FilterFactory.CVE_MATCHES_DESCRIPTION));

        //Mimic reconciler controller process
        VulnSetWrapper wrapper = new VulnSetWrapper(rawVulns);

        Set<RawVulnerability> firstWaveVulns = wrapper.firstFilterWave();
        //Calculate metrics for first wave
        Map<String, Set<RawVulnerability>> equivClasses = new HashMap<>();
        Set<RawVulnerability> samples = new HashSet<>(); // holds one from each equivalence class
        for (RawVulnerability rawVuln : firstWaveVulns) {
            String desc = rawVuln.getDescription();
            if (!equivClasses.containsKey(desc)) {
                equivClasses.put(desc, new HashSet<>());
                samples.add(rawVuln);
            }
            equivClasses.get(desc).add(rawVuln);
        }
        for (Filter filter : filters) {
            // filter.filterAll(samples); // todo filter technique
        }
        // update filter statuses in each equiv class to match its sample
        for (RawVulnerability sample : samples) {
            for (RawVulnerability rv : equivClasses.get(sample.getDescription())) {
                rv.setFilterStatus(sample.getFilterStatus());
            }
        }
        int numPassed = firstWaveVulns.stream().filter(v->v.getFilterStatus() == FilterStatus.PASSED).collect(Collectors.toSet()).size();
        System.out.println("Total in json: " + jArray.size());
        System.out.println("Total in first wave: " + firstWaveVulns.size());
        System.out.println("Accepted: " + numPassed);

        //Calculate metrics for second
        Set<RawVulnerability> secondWaveVulns = wrapper.secondFilterWave();
        Map<String, Set<RawVulnerability>> equivClasses2 = new HashMap<>();
        Set<RawVulnerability> samples2 = new HashSet<>(); // holds one from each equivalence class
        for (RawVulnerability rawVuln : secondWaveVulns) {
            String desc = rawVuln.getDescription();
            if (!equivClasses2.containsKey(desc)) {
                equivClasses2.put(desc, new HashSet<>());
                samples2.add(rawVuln);
            }
            equivClasses2.get(desc).add(rawVuln);
        }
        for (Filter filter : filters) {
            //filter.filterAll(samples2); // todo filter technique
        }
        // update filter statuses in each equiv class to match its sample
        for (RawVulnerability sample : samples2) {
            for (RawVulnerability rv : equivClasses2.get(sample.getDescription())) {
                rv.setFilterStatus(sample.getFilterStatus());
            }
        }
        int numPassed2 = secondWaveVulns.stream().filter(v->v.getFilterStatus() == FilterStatus.PASSED).collect(Collectors.toSet()).size();
        System.out.println("Total in json: " + jArray.size());
        System.out.println("Total in second wave: " + secondWaveVulns.size());
        System.out.println("Accepted: " + numPassed2);
    }

    public void analyzeCveForMatt() {
        String jsonPathFrom = "./src/main/java/edu/rit/se/nvip/sandbox/CrawlerOutputFull_6_22_2023.json";
//        String jsonPathTo = "./src/main/java/edu/rit/se/nvip/sandbox/CrawlerOutputFull_6_22_2023_NEW.json";
        LinkedHashMap<String, Integer> cveCounts = new LinkedHashMap<>();
        LinkedHashMap<String, String> cveSources = new LinkedHashMap<>();
        JsonArray jArray = null;
        try (FileReader reader = new FileReader(jsonPathFrom)) {
            JsonReader jReader = Json.createReader(reader);
            jArray = jReader.readArray();
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }
        for (int i = 0; i < jArray.size(); i++) {
            JsonObject jo = jArray.getJsonObject(i);
            String cveId = jo.getString("cve_id");
            String cveSource = jo.getString("source_url");
            String host = "";
            try {
                URI url = new URI(cveSource);
                host = url.getHost();
            } catch (URISyntaxException e) {
                e.printStackTrace();
            }

            if (cveCounts.containsKey(cveId)) {
//              Only increment if different domains
//                if (!cveSources.containsValue(host)) {
                    int currentCount = cveCounts.get(cveId);
                    cveCounts.put(cveId, currentCount+1);
                    cveSources.put(cveId, host);
//                }
            } else {
                cveCounts.put(cveId, 1);
                cveSources.put(cveId, host);
            }
        }
        for (String currentCveId: cveCounts.keySet()) {
            if (cveCounts.get(currentCveId) >=4) {
                createJson(jsonPathFrom, currentCveId);
            }
        }
    }

    private void createJson(String jsonPathFrom, String cveId) {
        JsonArray jArray = null;
        try (FileReader reader = new FileReader(jsonPathFrom)) {
            JsonReader jReader = Json.createReader(reader);
            jArray = jReader.readArray();
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }
        JsonArrayBuilder builder = Json.createArrayBuilder();
        Set<RawVulnerability> rawVulns = new HashSet<>();
        for (int i = 0; i < jArray.size(); i++) {
            JsonObject jo = jArray.getJsonObject(i);
            if (jo.getString("cve_id").equals(cveId)) {
                RawVulnerability rawVuln = new RawVulnerability(jo.getInt("raw_description_id"),
                        jo.getString("cve_id"),
                        jo.getString("raw_description"),
                        new Timestamp(jo.getJsonNumber("published_date").longValue()),
                        new Timestamp(jo.getJsonNumber("last_modified_date").longValue()),
                        new Timestamp(jo.getJsonNumber("created_date").longValue()),
                        jo.getString("source_url"),
                        jo.getString("source_type"),
                        jo.getInt("filter_status"));
                rawVulns.add(rawVuln);
            }
        }
        Set<Filter> filters = new HashSet<>();
        filters.add(FilterFactory.createFilter(FilterFactory.MULTIPLE_CVE_DESCRIPTION));
        filters.add(FilterFactory.createFilter(FilterFactory.BLANK_DESCRIPTION));
        filters.add(FilterFactory.createFilter(FilterFactory.INTEGER_DESCRIPTION));
        filters.add(FilterFactory.createFilter(FilterFactory.DESCRIPTION_SIZE));
        filters.add(FilterFactory.createFilter(FilterFactory.CVE_MATCHES_DESCRIPTION));

        //Run tests on collected set of vulns
        int numHighPrio = 0;
        int numLowPrio = 0;
        for (RawVulnerability rawVuln: rawVulns) {
            if (rawVuln.isHighPriority())
                numHighPrio++;
            else
                numLowPrio++;
        }

        //Analyze descriptions
        int numPassFilter = 0;
        int numFailFilter = 0;
        for (RawVulnerability rawVuln: rawVulns) {
            for (Filter filter: filters) {
                if (!filter.passesFilter(rawVuln)) {
                    numFailFilter++;
                    break;
                }
            }
            numPassFilter++;
        }

        if (numHighPrio != 0 && numLowPrio != 0 && numFailFilter != 0 && numPassFilter != 0) {
            for (RawVulnerability rawVuln: rawVulns) {
                JsonObjectBuilder job = Json.createObjectBuilder();
                job.add("raw_description_id", rawVuln.getId());
                job.add("raw_description", rawVuln.getDescription());
                job.add("cve_id", rawVuln.getCveId());
                job.add("created_date", rawVuln.getCreateDate().toString());
                job.add("published_date", rawVuln.getPublishDate().toString());
                job.add("last_modified_date", rawVuln.getLastModifiedDate().toString());
                job.add("source_url", rawVuln.getSourceUrl());
                job.add("source_type", rawVuln.getSourceType().type);
                job.add("filter_status", rawVuln.getFilterStatus().value);
                builder.add(job);
            }
            JsonArray ja = builder.build();

            try (FileWriter writer = new FileWriter("./src/main/java/edu/rit/se/nvip/sandbox/jsons/" + cveId + ".json")) {
                writer.write(ja.toString());
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

    }
}
