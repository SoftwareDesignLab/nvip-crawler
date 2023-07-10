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
package commits;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.Test;
import utils.GitController;

import java.io.File;
import java.util.List;
import java.util.regex.Pattern;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

//@RunWith(MockitoJUnitRunner.class)
public class PatchCommitScraperTest {
    private PatchCommitScraper patchCommitScraper;
    private static final Pattern[] patchPatterns = new Pattern[] {Pattern.compile("vulnerability|Vulnerability|vuln|Vuln|VULN[ #]*([0-9]+)")};


    @Test
    public void testParseCommits_NoCommitsFound() {
        String cveId = "CVE-2023-1001";
        Pattern[] patchPatterns = {Pattern.compile("fix")};

        PatchCommitScraper scraper = new PatchCommitScraper("local/repo", "https://github.com/example/repo");
        List<PatchCommit> patchCommits = scraper.parseCommits(cveId, patchPatterns);

        Assertions.assertEquals(0, patchCommits.size());
    }

    @Test
    public void testParseCommits() {
        String cveId = "CVE-2023-5678";
        Pattern[] patchPatterns = {Pattern.compile("patch")};

        // Set up the localDownloadLoc and repoSource
        String localDownloadLoc = "test-jgitparser/dash-core-components";
        String repoSource = "https://github.com/plotly/dash-core-components";

        // Clone the git repository
        GitController gitController = new GitController(localDownloadLoc, repoSource + ".git");
        gitController.cloneRepo();

        // Create the PatchCommitScraper instance
        PatchCommitScraper commitScraper = new PatchCommitScraper(localDownloadLoc, repoSource);

        // Call the parseCommits method
        List<PatchCommit> patchCommits = commitScraper.parseCommits(cveId, patchPatterns);

        // Assertions
        Assertions.assertEquals(11, patchCommits.size());
        PatchCommit patchCommit = patchCommits.get(0);
        Assertions.assertEquals(cveId, patchCommit.getCveId());

        // Delete the cloned repository
        gitController.deleteRepo();
    }
}
