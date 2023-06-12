package reconciler;

import reconciler.models.ApacheOpenNLPModel;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ApacheOpenNLPReconcilerTest {

    @Test
    void reconcileDescriptions() {
        // mock the model
        ApacheOpenNLPModel modelMock = mock(ApacheOpenNLPModel.class);
        doNothing().when(modelMock).initialize();
        when(modelMock.tag(any())).thenReturn(new String[]{"foo", "bar", "foobar"});
        when(modelMock.sentDetect(any())).thenReturn(new String[]{"foosent", "barsent", "foobarsent"});

        ApacheOpenNLPReconciler rec = new ApacheOpenNLPReconciler();
        rec.attachModel(modelMock);
        boolean decision = rec.reconcileDescriptions("blahblahblahblah", "blahblah", new HashSet<>(), "https://foo.com");
        decision = rec.reconcileDescriptions(null, null, new HashSet<>(), null);
        decision = rec.reconcileDescriptions(null, "foo", new HashSet<>(), "https://foo.bar");
        assertTrue(decision);
        Set<String> sources = new HashSet<>();
        sources.add("https://foo.bar");
        decision = rec.reconcileDescriptions("foo", null, sources, null);
        assertFalse(decision);
    }
}