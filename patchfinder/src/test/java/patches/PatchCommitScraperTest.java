package patches;

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

import org.junit.Assert;
import org.junit.jupiter.api.Assertions;
import org.junit.Test;
import utils.GitController;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

import static org.junit.Assert.fail;

/**
 * Unit tests for PatchCommitScraper class
 *
 * @author Richard Sawh
 */
public class PatchCommitScraperTest {

    @Test
    public void testParseCommits_NoCommitsFound() {
        String cveId = "CVE-2023-1001";
        Pattern[] patchPatterns = {Pattern.compile("fix")};

        PatchCommitScraper scraper = new PatchCommitScraper("local/repo", "https://github.com/example/repo");
        Set<PatchCommit> patchCommits = new HashSet<>();
        scraper.parseCommits(patchCommits, cveId);

        Assertions.assertEquals(0, patchCommits.size());
    }

    @Test
    public void testParseCommits() {
        String cveId = "CVE-2023-5678";
        Pattern[] patchPatterns = {Pattern.compile("patch")};

        // Set up the localDownloadLoc and repoSource
        String localDownloadLoc = "target/testrepo/dash-core-components";
        String repoSource = "https://github.com/plotly/dash-core-components";

        // Create a temporary directory to clone the repository
        Path tempDir;
        try {
            tempDir = Files.createTempDirectory("temp-repo");
        } catch (IOException e) {
            fail("Failed to create temporary directory for cloning repository");
            return;
        }

        // Clone the git repository
        GitController gitController = new GitController(tempDir.toString(), repoSource + ".git");
        gitController.cloneRepo();

        // Create the PatchCommitScraper instance
        PatchCommitScraper commitScraper = new PatchCommitScraper(tempDir.toString(), repoSource);

        // Call the parseCommits method
        Set<PatchCommit> patchCommits = new HashSet<>();
        commitScraper.parseCommits(patchCommits, cveId);

        // Assertions
        Assert.assertEquals(11, patchCommits.size());
        PatchCommit patchCommit = patchCommits.toArray(PatchCommit[]::new)[0];
        Assert.assertEquals(cveId, patchCommit.getCveId());

        // Delete the cloned repository
        gitController.deleteRepo();
    }
}
