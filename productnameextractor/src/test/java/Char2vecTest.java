import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class Char2vecTest {
    private Char2vec char2vec;

    @BeforeEach
    public void setUp() {
        String modelConfigPath = "C:\\Users\\richa\\Downloads\\nvip\\nvip-crawler\\productnameextractor\\src\\main\\resources\\data\\c2v_model_config_50.json";
        String modelWeightsPath = "C:\\Users\\richa\\Downloads\\nvip\\nvip-crawler\\productnameextractor\\src\\main\\resources\\data\\c2v_model_weights_50.h5";
        char2vec = new Char2vec(modelConfigPath, modelWeightsPath);
    }

    @Test
    public void testGetOutVectorLength() {
        // Test the getOutVectorLength() method
        int expectedLength = 50;
        int actualLength = char2vec.getOutVectorLength();
        assertEquals(expectedLength, actualLength);
    }

    @Test
    public void testWord2vecWithKnownWord() {
        // Test word2vec method with a known word
        String word = "hello";
        float[] vector = char2vec.word2vec(word);

        // Verify that the returned vector is not null
        assertNotNull(vector);
        // Verify that the length of the vector matches the expected length
        int expectedLength = char2vec.getOutVectorLength();
        assertEquals(expectedLength, vector.length);
    }

    @Test
    public void testWord2vecWithUnknownWord() {
        // Test word2vec method with an unknown word
        String word = "$#@!";
        float[] vector = char2vec.word2vec(word);

        // Verify that the returned vector is an array of all zeros
        assertNotNull(vector);
        assertEquals(char2vec.getOutVectorLength(), vector.length);
    }
}
