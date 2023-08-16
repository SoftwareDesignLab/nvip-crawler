package edu.rit.se.nvip.cwe;

import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.io.File;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockStatic;

class CweControllerTest {

    @Test
    void getCWEsFromWeb() {
        MockedStatic<CweController> mocked = mockStatic(CweController.class);
        mocked.when(() -> CweController.unzipFile(any(File.class), any(File.class))).thenReturn("{ \"key\": \"value\"}");
    }
}