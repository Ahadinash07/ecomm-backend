const { uploadToS3 } = require("../../middleware/awsmiddleware");
const db = require("../../Models/db");
const env = require("dotenv");
const { v4: uuidv4 } = require('uuid');
env.config();

// Enhanced safeJsonParse function
const safeJsonParse = (jsonString) => {
  if (!jsonString) return [];
  
  try {
    // If it's already an array, return it
    if (Array.isArray(jsonString)) return jsonString;
    
    // If it's a string, try to parse it
    const parsed = JSON.parse(jsonString);
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch (e) {
    // If it's a string but not JSON, treat as single image URL
    return typeof jsonString === 'string' ? [jsonString] : [];
  }
};

// Enhanced processProduct function
const processProduct = (product) => {
  // Process images with URL validation
  const processImageUrls = (urls) => {
    if (!urls || !Array.isArray(urls)) return [];
    return urls.map(url => {
      if (typeof url !== 'string') return null;
      // Ensure URL has proper protocol
      if (url.startsWith('//')) return `https:${url}`;
      if (!url.startsWith('http')) return `https://${url}`;
      return url;
    }).filter(url => url !== null);
  };

  return {
    ...product,
    images: processImageUrls(safeJsonParse(product.images)),
    videoUrl: product.videoUrl || null,
    colors: safeJsonParse(product.colors),
    sizes: safeJsonParse(product.sizes),
    materials: safeJsonParse(product.materials),
    features: safeJsonParse(product.features),
    descriptionImages: processImageUrls(safeJsonParse(product.description_images)),
    videos: safeJsonParse(product.videos),
    price: parseFloat(product.price) || 0,
    quantity: parseInt(product.quantity, 10) || 0,
    weight: product.weight ? parseFloat(product.weight) : null,
  };
};

// Add CORS headers middleware
const addCorsHeaders = (req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
  next();
};

// Updated GetProductDetailsController with debugging
const GetProductDetailsController = async (req, res) => {
  const { productId } = req.params;

  try {
    const query = `
      SELECT p.*, pd.colors, pd.sizes, pd.weight, pd.dimensions, pd.materials, 
             pd.features, pd.images AS description_images, pd.videos 
      FROM product p 
      LEFT JOIN product_descriptions pd ON p.productId = pd.productId 
      WHERE p.productId = ?
    `;

    db.query(query, [productId], (err, results) => {
      if (err) {
        console.error('Database Error:', err);
        return res.status(500).json({ 
          success: false,
          message: 'Database error',
          error: err.message 
        });
      }

      if (results.length === 0) {
        return res.status(404).json({ 
          success: false,
          message: 'Product not found' 
        });
      }

      const product = processProduct(results[0]);
      // console.log('Processed Product:', { id: product.productId, images: product.images, descImages: product.descriptionImages });

      return res.status(200).json({ 
        success: true,
        product 
      });
    });
  } catch (error) {
    console.error('Server Error:', error);
    return res.status(500).json({ 
      success: false,
      message: 'Internal server error',
      error: error.message 
    });
  }
};

const AddProductController = async (req, res) => {
  const { retailerId, productName, description, category, subcategory, brand, quantity, price } = req.body;

  if (!retailerId || !productName || !description || !category || !subcategory || !brand || !quantity || !price) {
    return res.status(400).json({ message: 'All product fields are required' });
  }

  // Validate price and quantity
  const numPrice = parseFloat(price);
  const numQuantity = parseInt(quantity, 10);
  if (isNaN(numPrice) || isNaN(numQuantity)) {
    return res.status(400).json({ message: 'Invalid price or quantity' });
  }

  if (!req.files || !req.files['images']) {
    return res.status(400).json({ message: 'Product images are required' });
  }

  try {
    const imageFiles = req.files['images'];
    const imageUrls = await Promise.all(
      imageFiles.map(async (file) => await uploadToS3(file))
    );

    let videoUrl = null;
    if (req.files['video'] && req.files['video'][0]) {
      videoUrl = await uploadToS3(req.files['video'][0]);
    }

    const productId = uuidv4();
    const addedAt = new Date().toISOString().slice(0, 19).replace('T', ' ');

    const insertProductQuery = `INSERT INTO product (productId, retailerId, productName, description, category, subcategory, brand, quantity, price, images, videoUrl, addedAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

    db.query(insertProductQuery, [
      productId,
      retailerId,
      productName,
      description,
      category,
      subcategory,
      brand,
      numQuantity,
      numPrice,
      JSON.stringify(imageUrls),
      videoUrl,
      addedAt
    ], (err, result) => {
      if (err) {
        console.error('Database Error:', err);
        return res.status(500).json({ message: 'Error in adding product' });
      }

      const product = {
        productId,
        retailerId,
        productName,
        description,
        category,
        subcategory,
        brand,
        quantity: numQuantity,
        price: numPrice,
        images: imageUrls,
        videoUrl,
        addedAt
      };

      return res.status(201).json({
        success: true,
        message: 'Product added successfully',
        product
      });
    });
  } catch (error) {
    console.error('Error in AddProductController:', error);
    return res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

const GetRetailerProductsController = async (req, res) => {
  const { retailerId } = req.params;

  try {
    const getProductsQuery = `SELECT * FROM product WHERE retailerId = ?`;
    db.query(getProductsQuery, [retailerId], (err, results) => {
      if (err) {
        console.error("Database Error:", err);
        return res.status(500).json({ message: 'Database error' });
      }

      const products = results.map(processProduct);

      if (products.length === 0) {
        return res.status(404).json({ message: 'No products found for this retailer.' });
      }
      return res.status(200).json({ products });
    });
  } catch (error) {
    console.error("Server Error:", error);
    return res.status(500).json({ message: 'Internal server error' });
  }
};



const SearchProductsController = async (req, res) => {
  const { query, category, subcategory, minPrice, maxPrice, brand, sort } = req.query;

  try {
    let searchQuery = `SELECT p.*, pd.colors, pd.sizes, pd.weight, pd.dimensions, pd.materials, pd.features, pd.images AS description_images, pd.videos 
      FROM product p 
      LEFT JOIN product_descriptions pd ON p.productId = pd.productId 
      WHERE 1=1`;
    
    const queryParams = [];

    if (query) {
      searchQuery += ` AND (p.productName LIKE ? OR p.description LIKE ? OR p.brand LIKE ?)`;
      queryParams.push(`%${query}%`, `%${query}%`, `%${query}%`);
    }

    if (category) {
      searchQuery += ` AND p.category = ?`;
      queryParams.push(category);
    }

    if (subcategory) {
      searchQuery += ` AND p.subcategory = ?`;
      queryParams.push(subcategory);
    }

    if (brand) {
      searchQuery += ` AND p.brand = ?`;
      queryParams.push(brand);
    }

    if (minPrice) {
      searchQuery += ` AND p.price >= ?`;
      queryParams.push(parseFloat(minPrice));
    }

    if (maxPrice) {
      searchQuery += ` AND p.price <= ?`;
      queryParams.push(parseFloat(maxPrice));
    }

    if (sort === 'price_asc') {
      searchQuery += ` ORDER BY p.price ASC`;
    } else if (sort === 'price_desc') {
      searchQuery += ` ORDER BY p.price DESC`;
    } else if (sort === 'newest') {
      searchQuery += ` ORDER BY p.addedAt DESC`;
    } else {
      searchQuery += ` ORDER BY p.productName ASC`;
    }

    db.query(searchQuery, queryParams, (err, results) => {
      if (err) {
        console.error('Database Error:', err);
        return res.status(500).json({ message: 'Database error' });
      }

      const products = results.map(processProduct);

      return res.status(200).json({ products });
    });
  } catch (error) {
    console.error('Server Error:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
};

const GetCategoriesController = async (req, res) => {
  try {
    const query = `SELECT DISTINCT category FROM product ORDER BY category`;
    
    db.query(query, (err, results) => {
      if (err) {
        console.error('Database Error:', err);
        return res.status(500).json({ message: 'Database error' });
      }

      const categories = results.map(row => row.category);
      return res.status(200).json({ categories });
    });
  } catch (error) {
    console.error('Server Error:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
};

const GetBrandsController = async (req, res) => {
  try {
    const query = `SELECT DISTINCT brand FROM product WHERE brand IS NOT NULL ORDER BY brand`;
    db.query(query, (err, results) => {
      if (err) {
        console.error('Database Error:', err);
        return res.status(500).json({ message: 'Database error' });
      }
      const brands = results.map(row => row.brand);
      return res.status(200).json({ brands });
    });
  } catch (error) {
    console.error('Server Error:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
};

const GetFeaturedProductsController = async (req, res) => {
  try {
    const query = `SELECT p.*, pd.colors, pd.sizes, pd.weight, pd.dimensions, pd.materials, pd.features, pd.images AS description_images, pd.videos 
      FROM product p 
      LEFT JOIN product_descriptions pd ON p.productId = pd.productId 
      ORDER BY p.addedAt DESC 
      LIMIT 8`;
    
    db.query(query, (err, results) => {
      if (err) {
        console.error('Database Error:', err);
        return res.status(500).json({ message: 'Database error' });
      }

      const products = results.map(processProduct);

      return res.status(200).json({ products });
    });
  } catch (error) {
    console.error('Server Error:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
};

const GetProductsBySubcategory = async (req, res) => {
  const { subCatId } = req.params;

  try {
    // First, get the subcategory name from subCatId
    const subCatQuery = `SELECT subCatName FROM subcategory WHERE subCatId = ?`;
    db.query(subCatQuery, [subCatId], (err, subCatResults) => {
      if (err) {
        console.error('Database Error:', err);
        return res.status(500).json({ message: 'Database error', error: err.message });
      }
      if (subCatResults.length === 0) {
        return res.status(404).json({ message: 'Subcategory not found' });
      }

      const subCatName = subCatResults[0].subCatName;
      const query = `
        SELECT p.*, pd.colors, pd.sizes, pd.weight, pd.dimensions, pd.materials, 
               pd.features, pd.images AS description_images, pd.videos 
        FROM product p 
        LEFT JOIN product_descriptions pd ON p.productId = pd.productId 
        WHERE p.subcategory = ?
      `;

      db.query(query, [subCatName], (err, results) => {
        if (err) {
          console.error('Database Error:', err);
          return res.status(500).json({ message: 'Database error', error: err.message });
        }

        const products = results.map(processProduct);
        return res.status(200).json({ products });
      });
    });
  } catch (error) {
    console.error('Server Error:', error);
    return res.status(500).json({ message: 'Internal server error', error: error.message });
  }
};

module.exports = {
  AddProductController,
  GetRetailerProductsController,
  SearchProductsController,
  GetProductDetailsController,
  GetCategoriesController,
  GetBrandsController,
  GetFeaturedProductsController,
  GetProductsBySubcategory
};