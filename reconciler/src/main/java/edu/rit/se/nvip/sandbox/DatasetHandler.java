package edu.rit.se.nvip.sandbox;

import edu.rit.se.nvip.filter.Filter;
import edu.rit.se.nvip.filter.FilterFactory;
import edu.rit.se.nvip.model.RawVulnerability;

import javax.json.*;
import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.sql.Timestamp;
import java.util.*;

public class DatasetHandler {
    String jsonPathRaw = "./src/main/java/edu/rit/se/nvip/sandbox/filter_dataset.json";

    String jsonPathLabeled = "./src/main/java/edu/rit/se/nvip/sandbox/filter_dataset_labeled.json";

    DatabaseSandbox db;
    public static void main(String[] args) {
        DatasetHandler dh = new DatasetHandler();
//        dh.jsonToDb();
//        dh.dbToJson();
        dh.updateJson("./src/main/java/edu/rit/se/nvip/sandbox/CrawlerOutputFull_6_22_2023.json");
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
            Set<RawVulnerability> currentRejected = filter.filterAllAndSplit(unFiltered);
            rejected.addAll(currentRejected);
            unFiltered.removeAll(currentRejected);
        }

        System.out.println("Total: " + jArray.size());
        System.out.println("Rejected Count: " + rejected.size());
        System.out.println("Accepted Count: " + unFiltered.size());
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
            ob.add("created_date", jo.getInt("created_date"));
            ob.add("published_date", jo.getInt("published_date"));
            ob.add("last_modified_date", jo.getInt("last_modified_date"));
            ob.add("source_url", jo.getString("source_url"));
            ob.add("source_type", currentSourceType);
            ob.add("filter_status", 1);
            builder.add(ob);
        }
        JsonArray ja = builder.build();

        try (FileWriter writer = new FileWriter(jsonPath)) {
            writer.write(ja.toString());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
