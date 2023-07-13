package edu.rit.se.nvip;

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

import edu.rit.se.nvip.model.cpe.CpeGroup;
import edu.rit.se.nvip.model.cpe.AffectedProduct;
import edu.rit.se.nvip.model.cve.CompositeVulnerability;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;
import java.util.List;

/**
 * Controller for the isolated ProductNameExtractor package.
 *
 * @author Dylan Mulligan
 */
public class ProductNameExtractorController {
    private static final Logger logger = LogManager.getLogger(ProductNameExtractorController.class);
    private static final int numThreads = ProductNameExtractorEnvVars.getNumThreads();
    private static final String resourceDir = ProductNameExtractorEnvVars.getResourceDir();
    private static final String dataDir = ProductNameExtractorEnvVars.getDataDir();
    private static final String nlpDir = ProductNameExtractorEnvVars.getNlpDir();
    private static AffectedProductIdentifier affectedProductIdentifier;
    private static Map<String, CpeGroup> productDict;

    /**
     * Initialize the AffectedProductIdentifier & related models
     * as well as load the product dictionary. If both have already been loaded,
     * controller is ready to process CVEs.
     */
    public static void initializeController(List<CompositeVulnerability> vulnList){
        if(affectedProductIdentifier == null){
            logger.info("Initializing the AffectedProductIdentifier...");
            affectedProductIdentifier = new AffectedProductIdentifier(numThreads, vulnList);
            affectedProductIdentifier.initializeProductDetector(resourceDir, nlpDir, dataDir);
        }else{
            logger.info("AffectedProductIdentifier already initialized!");
            affectedProductIdentifier.setVulnList(vulnList);
        }

        productDict = ProductDictionary.getProductDict();
        affectedProductIdentifier.loadProductDict(productDict);
    }

    /**
     * Releases the Affected Product Identifier and all of its models
     * as well as the product dictionary from memory.
     */
    protected static void releaseResources(){
        if(affectedProductIdentifier != null){
            affectedProductIdentifier.releaseResources();
            affectedProductIdentifier = null;
        }
        productDict = null;
    }

    /**
     * Runs the affectedProductIdentifier
     *
     * @return affected products found
     */
    public static List<AffectedProduct> run() {
        // Run the AffectedProductIdentifier and return the products found
        return affectedProductIdentifier.identifyAffectedProducts();
    }
}