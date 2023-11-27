package env;

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

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for class ProductNameExtractorEnvVars
 *
 * @author Paul Vickers
 */
public class ProductNameExtractorEnvVarsTest {

    /**
     * This test is written specifically to match up with the environment variables created in the GitHub yml file.
     * Because of this, it will likely fail locally unless your environment variables line up with the yml file.
     *
     * This will most likely be because of your working directory & RESOURCE_DIR env var. Test is made to work for
     * the productnameextractor working directory with RESOURCE_DIR = nvip_data, which is what the GitHub yml uses.
     */

    // @Test TODO: Bad test as it checks values in the properties, not testing the retrieval of them
    public void initializeAndGetEnvVarsTest(){
        ProductNameExtractorEnvVars.initializeEnvVars();

        // Default values for main environment variables
        assertEquals(12, ProductNameExtractorEnvVars.getNumThreads());
        assertEquals(5, ProductNameExtractorEnvVars.getMaxAttemptsPerPage());
        assertFalse(ProductNameExtractorEnvVars.isPrettyPrint());
        assertFalse(ProductNameExtractorEnvVars.isTestMode());
        assertEquals("product_dict.json", ProductNameExtractorEnvVars.getProductDictName());
        assertEquals(1.0, ProductNameExtractorEnvVars.getRefreshInterval());
        assertEquals(14.0, ProductNameExtractorEnvVars.getFullPullInterval());
        assertEquals("nvip_data", ProductNameExtractorEnvVars.getResourceDir());
        assertEquals("data", ProductNameExtractorEnvVars.getDataDir());
        assertEquals("nlp", ProductNameExtractorEnvVars.getNlpDir());

        // Default values for database environment variables
        assertEquals("mysql", ProductNameExtractorEnvVars.getDatabaseType());
        assertEquals("jdbc:mysql://localhost:3306/nvip?useSSL=false&allowPublicKeyRetrieval=true", ProductNameExtractorEnvVars.getHikariUrl());
        assertEquals("root", ProductNameExtractorEnvVars.getHikariUser());
        assertEquals("root", ProductNameExtractorEnvVars.getHikariPassword());

        // Default values for model environment variables
        assertEquals("en-pos-perceptron.bin", ProductNameExtractorEnvVars.getProductDetectorModel());
        assertEquals("c2v_model_config_50.json", ProductNameExtractorEnvVars.getChar2VecConfig());
        assertEquals("c2v_model_weights_50.h5", ProductNameExtractorEnvVars.getChar2VecWeights());
        assertEquals("w2v_model_250.bin", ProductNameExtractorEnvVars.getWord2Vec());
        assertEquals("NERallModel.bin", ProductNameExtractorEnvVars.getNerModel());
        assertEquals("NERallNorm.bin", ProductNameExtractorEnvVars.getNerModelNormalizer());
        assertEquals("en-sent.bin", ProductNameExtractorEnvVars.getSentenceModel());

        // Default values for RabbitMQ environment variables
        assertEquals(60, ProductNameExtractorEnvVars.getRabbitPollInterval());
        assertEquals("host.docker.internal", ProductNameExtractorEnvVars.getRabbitHost());
        assertEquals("guest", ProductNameExtractorEnvVars.getRabbitUsername());
        assertEquals("guest", ProductNameExtractorEnvVars.getRabbitPassword());
        assertEquals("RECONCILER_OUT", ProductNameExtractorEnvVars.getRabbitInputQueue());
        assertEquals("PNE_OUT_PATCH", ProductNameExtractorEnvVars.getRabbitPatchfinderOutputQueue());
        assertEquals("PNE_OUT_FIX", ProductNameExtractorEnvVars.getRabbitFixfinderOutputQueue());

    }
}
