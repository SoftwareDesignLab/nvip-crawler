package edu.rit.se.nvip.db.repositories;

import edu.rit.se.nvip.db.model.AffectedProduct;
import edu.rit.se.nvip.db.model.CpeCollection;
import edu.rit.se.nvip.db.model.CpeGroup;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;


@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ProductRepositoryTest {

    @Mock
    DataSource dataSource;
    @Mock
    Connection mockConnection;
    @Mock
    PreparedStatement mockPS;
    @Mock
    ResultSet mockRS;

    ProductRepository repository;



    @SneakyThrows
    @BeforeEach
    void initializeMocks(){
        when(mockPS.executeQuery()).thenReturn(mockRS);
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPS);
        when(dataSource.getConnection()).thenReturn(mockConnection);

        repository = new ProductRepository(dataSource);
    }

    private List<AffectedProduct> buildDummyProducts(int count) {
        List<AffectedProduct> products = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            String cpeName = "cpe:2.3:a:" + i + ":" + i + ":*:*:*:*:*:*:*:*";
            products.add(new AffectedProduct("cve"+i, cpeName, "productName"+i, "version"+i, "vendor"+i));
        }
        return products;
    }

    /**
     * Tests the insertAffectedProducts method. In this case since there are 5 products,
     * there should be 8 psmt.setStrings() so 8x5=40
     *
     * @throws SQLException
     */
    //@Test
    @SneakyThrows
    public void insertAffectedProductsTest() {
        int inCount = 5;
        List<AffectedProduct> products = buildDummyProducts(inCount);
        repository.insertAffectedProducts(new CpeCollection(null, products));
        try {
            verify(mockPS, times(inCount*7)).setString(anyInt(), any());
            verify(mockPS, times(inCount)).executeUpdate();
            verify(mockPS).setString(1, products.get(inCount-1).getCveId());
        } catch (SQLException ignored) {}
    }


    //	@Test
    public void testInsertAffectedProductsToDB() {
        //dont actually want to insert anything into the db
        repository = spy(repository);
        doNothing().when(repository).insertAffectedProducts(any());
        repository.insertAffectedProductsToDB(new ArrayList<>());
        verify(repository).insertAffectedProducts(any());
    }

    //	@Test
    public void deleteAffectedProductsTest() {
        int count = 5;
        List<AffectedProduct> products = buildDummyProducts(count);
        repository.deleteAffectedProducts(products);
        try {
            verify(mockPS, times(count)).setString(anyInt(), any());
            verify(mockPS, times(count)).executeUpdate();
            verify(mockPS).setString(1, products.get(count-1).getCveId());
        } catch (SQLException ignored) {}
    }

    @Test
    public void testGetAffectedProducts() {
        Map<String, CpeGroup> affectedProducts = repository.getAffectedProducts(null);
        assertNotNull(affectedProducts);
    }

}