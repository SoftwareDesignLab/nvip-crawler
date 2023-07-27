package utils;

import org.junit.Before;
import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

public class GitControllerTest {
    private static final String LOCAL_PATH = "src/main/resources/patch-repos";

    private static final String REMOTE_PATH = "https://github.com/apache/airflow.git";
    private GitController gitController;

    @Before
    public void setup() {
        gitController = new GitController(LOCAL_PATH, REMOTE_PATH);
        gitController.deleteRepo();
    }

    @Test
    public void testRepoCreation() {
        Path path = Paths.get(LOCAL_PATH);
        assertFalse(Files.exists(path));
        assertTrue(gitController.cloneRepo());
        assertTrue(gitController.pullRepo());
        assertTrue(Files.exists(path));
    }

    @Test
    public void testRepoDeletion() {
        gitController.deleteRepo();
        assertFalse(Files.exists(Paths.get(LOCAL_PATH)));
    }

}