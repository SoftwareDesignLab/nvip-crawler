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

import org.junit.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for class PatchFinderEnvVars class
 *
 * @author Paul Vickers
 */
public class PatchFinderEnvVarsTest {

    @Test
    public void initializeAndGetEnvVarsTest(){
        PatchFinderEnvVars.initializeEnvVars();

        // Default values for main environment variables
        assertEquals(20, PatchFinderEnvVars.getCveLimit());
        String[] addressBases = PatchFinderEnvVars.getAddressBases();
        assertEquals(addressBases[0], "https://www.github.com/");
        assertEquals(addressBases[1], "https://www.gitlab.com/");
        assertEquals(1000, PatchFinderEnvVars.getCloneCommitThreshold());
        assertEquals(50000, PatchFinderEnvVars.getCloneCommitLimit());
        assertEquals("nvip_data/patch-repos", PatchFinderEnvVars.getClonePath());
        assertEquals("nvip_data/source_dict.json", PatchFinderEnvVars.getPatchSrcUrlPath());

        // Default values for database environment variables
        assertEquals("mysql", PatchFinderEnvVars.getDatabaseType());
        assertEquals("jdbc:mysql://localhost:3306/nvip?useSSL=false&allowPublicKeyRetrieval=true", PatchFinderEnvVars.getHikariUrl());
        assertEquals("root", PatchFinderEnvVars.getHikariUser());
        assertEquals("root", PatchFinderEnvVars.getHikariPassword());

        // Default values for RabbitMQ environment variables
        assertEquals(60, PatchFinderEnvVars.getRabbitPollInterval());
        assertEquals("host.docker.internal", PatchFinderEnvVars.getRabbitHost());
        assertEquals("guest", PatchFinderEnvVars.getRabbitUsername());
        assertEquals("guest", PatchFinderEnvVars.getRabbitPassword());

    }
}
