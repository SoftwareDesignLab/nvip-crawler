/**
* Copyright 2021 Rochester Institute of Technology (RIT). Developed with
* government support under contract 70RCSA22C00000008 awarded by the United
* States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the “Software”), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

package edu.rit.se.nvip.crawler.github;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;


public class PyPaYamlFileTest {

    private final Path pypaResources = Paths.get("src", "test", "resources", "crawler", "github", "pypa");

    @Test
    public void test_from_pysec_2023_173(){
        PyPAYamlFile expected = new PyPAYamlFile(
                "PYSEC-2023-173",
                "Piccolo is an ORM and query builder which supports asyncio. In versions 0.120.0" +
                        " and prior, the implementation of `BaseUser.login` leaks enough information to a" +
                        " malicious user such that they would be able to successfully generate a list of valid" +
                        " users on the platform. As Piccolo on its own does not also enforce strong passwords," +
                        " these lists of valid accounts are likely to be used in a password spray attack with" +
                        " the outcome being attempted takeover of user accounts on the platform. The impact" +
                        " of this vulnerability is minor as it requires chaining with other attack vectors" +
                        " in order to gain more then simply a list of valid users on the underlying platform." +
                        " The likelihood of this vulnerability is possible as it requires minimal skills to" +
                        " pull off, especially given the underlying login functionality for Piccolo based" +
                        " sites is open source. This issue has been patched in version 0.121.0.",
                "Tue Sep 12 21:15:00 UTC 2023",
                "Tue Sep 19 05:26:00 UTC 2023",
                List.of("CVE-2023-41885", "GHSA-h7cm-mrvq-wcfr")
        );

        File pysec173Yaml = pypaResources.resolve(Paths.get("PYSEC-2023-173.yaml")).toFile();
        PyPAYamlFile actual = PyPAYamlFile.from(pysec173Yaml);

        assertEquals(expected, actual);
    }

    @Test
    public void test_from_pysec_2023_174(){
        PyPAYamlFile expected = new PyPAYamlFile(
                "PYSEC-2023-174",
                "imagecodecs versions before v2023.9.18 bundled libwebp binaries in wheels" +
                        " that are vulnerable to CVE-2023-4863. imagecodecs v2023.9.18 upgrades the bundled" +
                        " libwebp binary to v1.3.2.",
                "",
                "Wed Sep 20 05:12:42 UTC 2023",
                List.of()
        );

        File pysec174Yaml = pypaResources.resolve(Paths.get("PYSEC-2023-174.yaml")).toFile();

        PyPAYamlFile actual = PyPAYamlFile.from(pysec174Yaml);

        assertEquals(expected, actual);
    }

    @Test
    public void test_get_cves_with_no_cves_returns_empty_list(){
        List<String> expected = List.of();

        PyPAYamlFile pyPaFile = new PyPAYamlFile(
                "",
                "",
                "",
                "",
                List.of()
        );

        assertEquals(expected, pyPaFile.getCves());
    }

    @Test
    public void test_get_cves_returns_only_cves(){
        List<String> expected = List.of("CVE-2023-41885");

        PyPAYamlFile pyPaFile = new PyPAYamlFile(
                "",
                "",
                "",
                "",
                List.of("CVE-2023-41885", "GHSA-h7cm-mrvq-wcfr")
        );

        assertEquals(expected, pyPaFile.getCves());
    }
}
