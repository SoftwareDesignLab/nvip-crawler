package utils;

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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for GitController class
 *
 * @author Richard Sawh
 */
public class GitControllerTest {
    private static final String LOCAL_PATH = "apache-airflow";

    private static final String REMOTE_PATH = "https://github.com/apache/airflow";
    private GitController gitController;

    @BeforeEach
    public void setup() {
        gitController = new GitController(LOCAL_PATH, REMOTE_PATH);
    }

    @AfterEach
    public void teardown() {
        gitController.deleteRepo();
    }

    @Test
    @Disabled("Until we figure out why the GitHub runner fails this test")
    public void testRepoCreation() {
        Path path = Paths.get(LOCAL_PATH);
        assertFalse(Files.exists(path));

        // Clone repo, assert success and that local repo destination is created
        assertTrue(gitController.cloneRepo());
        assertTrue(Files.exists(path));
    }

    @Test
    public void testRepoDeletion() {
        // Clone repo before deletion
        final Path path = Paths.get(LOCAL_PATH);
        gitController.cloneRepo();
        
        // Delete and assert local directory is non-existent
        gitController.deleteRepo();
        assertFalse(Files.exists(path));
    }
}