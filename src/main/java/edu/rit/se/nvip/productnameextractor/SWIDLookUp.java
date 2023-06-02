package edu.rit.se.nvip.productnameextractor;

import edu.rit.se.nvip.model.Product;

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

    private final Map<String, Product> productsToBeAddedToDatabase;


    private SWIDLookUp() {
        productsToBeAddedToDatabase = new HashMap<>();
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

    public Map<String, Product> getProductsToBeAddedToDatabase() {
        return productsToBeAddedToDatabase;
    }

    /**
     * Add swid entry to the database if it is not already there, add to the corresponding product
     */
    public void addProductToDatabase(Product p) {
        productsToBeAddedToDatabase.put(p.getSwid(), p);
    }

    /**
     * Generate a SWID tag for a productitem and add it to the SWID dictionary.
     *
     * @param  p The product item to add.
     */
    public void addSWIDEntry(ProductItem p) {
        //if the product name is not in the dictionary, add it
        if (!swidDictionary.containsKey(p.getName())) {
            List<SWIDEntry> entries = new ArrayList<>();
            entries.add(new SWIDEntry(p.getName(), generateSWID(p.getName(), p)));
            swidDictionary.put(p.getName(), entries);
            p.setSwid(generateSWID(p.getName(), p));
        } else {
            //if the product name is in the dictionary, check if the swid tag is already there
            List<SWIDEntry> entries = swidDictionary.get(p.getName());
            boolean swidExists = false;
            for (SWIDEntry entry : entries) {
                if (entry.getSWID().equals(p.getSwid())) {
                    swidExists = true;
                    break;
                }
            }
            //if the swid tag is not there, add it
            if (!swidExists) {
                p.setSwid(generateSWID(p.getName(), p));
                entries.add(new SWIDEntry(p.getName(), p.getSwid()));
            }
        }
        //add the product to the database, version needs to be a string for the product
        Product product = new Product(p.getName(), p.getSwid(), p.getVersions().get(0));
        addProductToDatabase(product);
    }



    /**
     * If a swid tag does not exist for a product name, generate one
     * @param productName
     * @return
     */
    public String generateSWID(String productName, ProductItem p) {
        SWIDgenerator swidgenerator = new SWIDgenerator();
        String swid = swidgenerator.generateSWID(p);
        return swid;
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
