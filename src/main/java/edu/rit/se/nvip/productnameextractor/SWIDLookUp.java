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
     * @param productName The product name.
     */
    public void addSWIDEntry(String productName, String swid) {
        SWIDEntry entry = new SWIDEntry(productName, swid);

        List<SWIDEntry> entryList = swidDictionary.get(productName);
        //if there is already an entry for the product name, do not add it again
        if (entryList == null) {
            entryList = new ArrayList<>();
            entryList.add(entry);
            swidDictionary.put(productName, entryList);
        } else {
            //if there is already an entry for the product name, check if the SWID is already in the list
            boolean swidExists = false;
            for (SWIDEntry e : entryList) {
                if (e.getSWID().equals(swid)) {
                    swidExists = true;
                    break;
                }
            }
            //if the SWID is not in the list, add it
            if (!swidExists) {
                entryList.add(entry);
            }
        }
    }

    /**
     * Retrieves SWID entries based on a product name.
     *
     * @param productName The product name to search for.
     * @return A list of SWID entries matching the product name.
     */
    public List<SWIDEntry> getSWIDEntries(String productName) {
        return swidDictionary.get(productName);
    }

    //get swid tag from SWID dictionary
    public String getSWID(String productName) {
        List<SWIDEntry> entries = swidDictionary.get(productName);
        if (entries != null) {
            return entries.get(0).getSWID();
        } else {
            return "";
        }
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
