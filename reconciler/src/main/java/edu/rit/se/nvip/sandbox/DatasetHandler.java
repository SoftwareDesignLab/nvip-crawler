package edu.rit.se.nvip.sandbox;

import edu.rit.se.nvip.model.RawVulnerability;

import javax.json.*;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.sql.Timestamp;
import java.util.*;

public class DatasetHandler {
    String jsonPath = "./src/main/java/edu/rit/se/nvip/sandbox/filter_dataset.json";
    DatabaseSandbox db;
    public static void main(String[] args) {
        DatasetHandler dh = new DatasetHandler();
        dh.jsonToDb();
    }

    public DatasetHandler() {
        db = DatabaseSandbox.getInstance("jdbc:mysql://localhost:3306/nviptest?useSSL=false&allowPublicKeyRetrieval=true",
                "root",
                "root");
    }
    public void jsonToDb() {
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
        Map<RawVulnerability, Integer> vulns = new HashMap<>();
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

    public void dbToJson() {
        Map<RawVulnerability, Integer> vulnMap = db.getFilterDataset();
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
            ob.add("is_garbage", vulnMap.get(vuln));
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
