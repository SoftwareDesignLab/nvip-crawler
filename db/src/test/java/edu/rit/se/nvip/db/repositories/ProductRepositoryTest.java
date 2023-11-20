package edu.rit.se.nvip.db.repositories;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class ProductRepositoryTest {

    // todo update these tests
    //	/**
    //	 * Tests the insertAffectedProducts method. In this case since there are 5 products,
    //	 * there should be 8 psmt.setStrings() so 8x5=40
    //	 *
    //	 * @throws SQLException
    //	 */
    ////	@Test
    //	public void insertAffectedProductsTest() {
    //		int inCount = 5;
    //		List<AffectedProduct> products = buildDummyProducts(inCount);
    //		dbh.insertAffectedProducts(new CpeCollection(null, products));
    //		try {
    //			verify(pstmt, times(inCount*7)).setString(anyInt(), any());
    //			verify(pstmt, times(inCount)).executeUpdate();
    //			verify(pstmt).setString(1, products.get(inCount-1).getCveId());
    //		} catch (SQLException ignored) {}
    //	}


//    //	@Test
//    public void testInsertAffectedProductsToDB() {
//        //dont actually want to insert anything into the db
//        dbh = spy(dbh);
//        doNothing().when(dbh).insertAffectedProducts(any());
//        dbh.insertAffectedProductsToDB(new ArrayList<>());
//        verify(dbh).insertAffectedProducts(any());
//    }

//    //	@Test
//    public void deleteAffectedProductsTest() {
//        int count = 5;
//        List<AffectedProduct> products = buildDummyProducts(count);
//        dbh.deleteAffectedProducts(products);
//        try {
//            verify(pstmt, times(count)).setString(anyInt(), any());
//            verify(pstmt, times(count)).executeUpdate();
//            verify(pstmt).setString(1, products.get(count-1).getCveId());
//        } catch (SQLException ignored) {}
//    }
//private List<AffectedProduct> buildDummyProducts(int count) {
//    List<AffectedProduct> products = new ArrayList<>();
//    for (int i = 0; i < count; i++) {
//        String cpeName = "cpe:2.3:a:" + i + ":" + i + ":*:*:*:*:*:*:*:*";
//        products.add(new AffectedProduct("cve"+i, cpeName, "productName"+i, "version"+i, "vendor"+i));
//    }
//    return products;
//}

}