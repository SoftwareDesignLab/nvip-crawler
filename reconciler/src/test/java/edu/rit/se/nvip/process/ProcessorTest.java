package process;

import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.jupiter.api.Test;

import java.util.Set;

class ProcessorTest {

    @Test
    void process() {
        Processor p = new Processor() {
            @Override
            public void process(Set<CompositeVulnerability> vulns) {
                return;
            }
        };
        // that's all! just making sure the implementation requirements didn't change
    }
}