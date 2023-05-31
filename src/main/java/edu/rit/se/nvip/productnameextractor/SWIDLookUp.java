package edu.rit.se.nvip.productnameextractor;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class is used to look up SWID entries based on product names in a SWID dictionary.
 */
public class SWIDLookUp {

    private static SWIDLookUp instance;
    private Map<String, List<SWIDEntry>> swidDictionary;

    private SWIDLookUp() {
        swidDictionary = new HashMap<>();
    }

    /**
     * Retrieves the singleton instance of the SWIDLookUp class.
     *
     * @return The singleton instance.
     */
    public static SWIDLookUp getInstance() {
        if (instance == null) {
            synchronized (SWIDLookUp.class) {
                if (instance == null) {
                    instance = new SWIDLookUp();
                }
            }
        }
        return instance;
    }

    /**
     * Adds a SWID entry to the SWID dictionary.
     *
     * @param entry The SWID entry to add.
     */
    public void addSWIDEntry(SWIDEntry entry) {
        String productName = entry.getProductName();

        if (swidDictionary.containsKey(productName)) {
            swidDictionary.get(productName).add(entry);
        } else {
            List<SWIDEntry> entryList = new ArrayList<>();
            entryList.add(entry);
            swidDictionary.put(productName, entryList);
        }
    }

    /**
     * Retrieves SWID entries based on a product name.
     *
     * @param productName The product name to search for.
     * @return A list of SWID entries matching the product name.
     */
    public List<SWIDEntry> getSWIDEntries(String productName) {
        List<SWIDEntry> entries = swidDictionary.get(productName);
        return (entries != null) ? entries : new ArrayList<>();
    }

    /**
     * Represents a SWID entry.
     */
    public static class SWIDEntry {
        private String productName;
        private String swid;

        public SWIDEntry(String productName, String swid) {
            this.productName = productName;
            this.swid = swid;
        }

        public String getProductName() {
            return productName;
        }

        public String getSWID() {
            return swid;
        }
    }
}
