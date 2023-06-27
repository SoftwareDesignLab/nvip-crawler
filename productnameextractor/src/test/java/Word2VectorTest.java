import edu.rit.se.nvip.Word2Vector;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class Word2VectorTest {
    private static Word2Vector word2Vector;

    @BeforeAll
    public static void setUp() {
        // Initialize the Word2Vector instance with the model file path
        String modelPath = "nvip_data/data/w2v_model_250.bin";
        word2Vector = new Word2Vector(modelPath);
    }

    @Test
    public void testGetOutVectorLength() {
        // Verify that the expected vector length is greater than 0
        int vectorLength = word2Vector.getOutVectorLength();
        assertTrue(vectorLength > 0);
    }

    @Test
    public void testWord2Vector() {
        // Test word2vector method with a known word
        String word = "example";
        double[] vector = word2Vector.word2vector(word);

        // Verify that the returned vector is not null
        assertNotNull(vector);

        // Verify that the length of the returned vector matches the expected vector length
        int expectedVectorLength = word2Vector.getOutVectorLength();
        assertEquals(expectedVectorLength, vector.length);
    }

    @Test
    public void testWord2VectorWithUnknownWord() {
        // Test word2vector method with an unknown word
        String word = "eiwnfubeg";
        double[] vector = word2Vector.word2vector(word);

        // Verify that the returned vector is null for unknown words
        assertNull(vector);
//        assertArrayEquals(new double[0], vector);

    }

    @Test
    public void testWord2VectorWithEmptyWord() {
        // Test word2vector method with an empty word
        String word = "";
        double[] vector = word2Vector.word2vector(word);

        // Verify that the returned vector is null for empty words
        assertNull(vector);
    }
}
