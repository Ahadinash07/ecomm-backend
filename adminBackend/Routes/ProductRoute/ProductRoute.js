const express = require('express');
const { 
  GetRetailerProductsController, 
  AddProductController,
  SearchProductsController,
  GetProductDetailsController,
  GetCategoriesController,
  GetBrandsController,
  GetFeaturedProductsController,
  GetProductsBySubcategory
} = require('../../Controllers/ProductController/ProductController');
const { upload } = require('../../middleware/awsmiddleware');
const corsMiddleware = require('../../middleware/corsMiddleware');

const ProductRoute = express.Router();

// Apply CORS middleware to all product routes
ProductRoute.use(corsMiddleware);

// Product CRUD operations
ProductRoute.post('/addProduct', 
  upload.fields([ 
    { name: 'images', maxCount: 5 }, 
    { name: 'video', maxCount: 1 } 
  ]), 
  AddProductController
);

ProductRoute.get('/getRetailerProducts/:retailerId', GetRetailerProductsController);

// Product search and discovery
ProductRoute.get('/search', SearchProductsController);
ProductRoute.get('/details/:productId', GetProductDetailsController);
ProductRoute.get('/categories', GetCategoriesController);
ProductRoute.get('/brands', GetBrandsController);
ProductRoute.get('/featured', GetFeaturedProductsController);
ProductRoute.get('/subcategory/:subCatId', GetProductsBySubcategory);

// Debug endpoint
ProductRoute.get('/debug/images/:productId', async (req, res) => {
  try {
    const { productId } = req.params;
    const query = 'SELECT images FROM product WHERE productId = ?';
    
    db.query(query, [productId], (err, results) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      
      if (results.length === 0) {
        return res.status(404).json({ message: 'Product not found' });
      }
      
      const rawImages = results[0].images;
      const parsedImages = safeJsonParse(rawImages);
      
      res.json({
        productId,
        rawImages,
        parsedImages,
        firstImageUrl: parsedImages[0] || null
      });
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = ProductRoute;




// const express = require('express');
// const { 
//   GetRetailerProductsController, 
//   AddProductController,
//   SearchProductsController,
//   GetProductDetailsController,
//   GetCategoriesController,
//   GetBrandsController,
//   GetFeaturedProductsController,
// } = require('../../Controllers/ProductController/ProductController');
// const { upload } = require('../../middleware/awsmiddleware');
// const ProductRoute = express.Router();

// // Product CRUD operations
// ProductRoute.post('/addProduct', 
//   upload.fields([ 
//     { name: 'images', maxCount: 5 }, 
//     { name: 'video', maxCount: 1 } 
//   ]), 
//   AddProductController
// );

// ProductRoute.get('/getRetailerProducts/:retailerId', GetRetailerProductsController);

// // Product search and discovery
// ProductRoute.get('/search', SearchProductsController);
// ProductRoute.get('/details/:productId', GetProductDetailsController);
// ProductRoute.get('/categories', GetCategoriesController);
// ProductRoute.get('/brands', GetBrandsController);
// ProductRoute.get('/featured', GetFeaturedProductsController);

// module.exports = ProductRoute;