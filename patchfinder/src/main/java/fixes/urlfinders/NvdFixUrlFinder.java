package fixes.urlfinders;

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

import fixes.FixFinder;

import java.io.IOException;
import java.util.ArrayList;

/**
 *  Implementation of FixUrlFinder for CVEs collected from NVD
 *
 *  @author Richard Sawh
 */
public class NvdFixUrlFinder extends FixUrlFinder {

    public NvdFixUrlFinder() { }

    @Override
    public ArrayList<String> run(String cveId) throws IOException {
        logger.info("Getting fixes for CVE: {}", cveId);
        ArrayList<String> urlList = new ArrayList<>();

        // Get all sources for the cve
        ArrayList<String> sources = FixFinder.getDatabaseHelper().getCveSourcesNVD(cveId);

        // Test each source for a valid connection
        for (String source : sources) {
            // Test reported source
            if (testConnection(source)) {
                urlList.add(source);
            }
        }

        // Test NVD direct cve page
        final String directSource = "https://nvd.nist.gov/vuln/detail/" + cveId;
        if(testConnection(directSource)) {
            urlList.add(directSource);
        }

        return urlList;
    }
}