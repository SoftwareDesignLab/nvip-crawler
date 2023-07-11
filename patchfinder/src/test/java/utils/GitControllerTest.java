package utils;

import org.junit.Before;
import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class GitControllerTest {
    private static final String LOCAL_PATH = "testrepo";

    private static final String REMOTE_PATH = "https://github.com/apache/airflow.git";
    private GitController gitController;

    @Before
    public void setup() {
        gitController = new GitController(LOCAL_PATH, REMOTE_PATH);
        gitController.deleteRepo();

    }


    @Test
    public void testRepo() {
        assertFalse(Files.exists(Paths.get(LOCAL_PATH)));
        assertTrue(gitController.cloneRepo());
        assertTrue(gitController.pullRepo());
    }

    @Test
    public void testMain_DeleteRepo() {
        // Create a mock GitController
        GitController gitMock = mock(GitController.class);

        // Invoke the method under test
        GitController.main(new String[]{});

        // Verify the behavior and result
        assertTrue(Files.exists(Paths.get(LOCAL_PATH)));
    }

}