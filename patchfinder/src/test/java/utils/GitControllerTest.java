package utils;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

public class GitControllerTest {
    private static final String LOCAL_PATH = "testrepo";

    private static final String REMOTE_PATH = "https://github.com/apache/airflow.git";
    private GitController gitController;

    @BeforeEach
    public void setup() {
        gitController = new GitController(LOCAL_PATH, REMOTE_PATH);
        gitController.deleteRepo();

    }


    @Test
    public void testRepo(){
        if(Files.exists(Paths.get(LOCAL_PATH))){
            gitController.deleteRepo();
            assertFalse(Files.exists(Paths.get(LOCAL_PATH)));
        }
        assertTrue(gitController.cloneRepo());
        assertTrue(gitController.pullRepo());
    }

}