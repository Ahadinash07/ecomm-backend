const db = require('../../Models/db');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    console.error('No token provided');
    return res.status(401).json({ message: 'Unauthorized' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      console.error('Token verification error:', err);
      return res.status(401).json({ message: 'Invalid token' });
    }
    if (!decoded.user_id) {
      console.error('Token missing user_id:', decoded);
      return res.status(401).json({ message: 'Invalid token payload' });
    }
    req.userId = decoded.user_id;
    next();
  });
};

// Add to cart
const addToCart = (req, res) => {
  const { productId, quantity } = req.body;
  const userId = req.userId;
  const MAX_QUANTITY_PER_PRODUCT = 6;

  if (!productId || !quantity || quantity < 1) {
    return res.status(400).json({ message: 'Invalid product ID or quantity' });
  }

  // Check if product exists and get its stock
  const productQuery = 'SELECT quantity, price, productName, images FROM product WHERE productId = ?';
  db.query(productQuery, [productId], (err, productResults) => {
    if (err) {
      console.error('Database error fetching product:', err);
      return res.status(500).json({ message: 'Server error' });
    }
    if (productResults.length === 0) {
      return res.status(404).json({ message: 'Product not found' });
    }

    const product = productResults[0];
    const availableQuantity = parseInt(product.quantity, 10);

    // Check if product already exists in cart
    const cartQuery = 'SELECT cartId, quantity FROM cart WHERE userId = ? AND productId = ?';
    db.query(cartQuery, [userId, productId], (err, cartResults) => {
      if (err) {
        console.error('Database error checking cart:', err);
        return res.status(500).json({ message: 'Server error' });
      }

      if (cartResults.length > 0) {
        // Product exists in cart, update quantity
        const currentQuantity = parseInt(cartResults[0].quantity, 10);
        const newQuantity = currentQuantity + quantity;
        const cartId = cartResults[0].cartId;

        if (newQuantity > MAX_QUANTITY_PER_PRODUCT) {
          return res.status(400).json({
            message: `Cannot add more than ${MAX_QUANTITY_PER_PRODUCT} units of this product`,
          });
        }
        if (newQuantity > availableQuantity) {
          return res.status(400).json({
            message: `Cannot add more; only ${availableQuantity} units available`,
          });
        }

        const updateQuery = 'UPDATE cart SET quantity = ? WHERE cartId = ?';
        db.query(updateQuery, [newQuantity, cartId], (err, result) => {
          if (err) {
            console.error('Database error updating cart:', err);
            return res.status(500).json({ message: 'Failed to update cart' });
          }
          res.status(200).json({ message: 'Quantity updated in cart' });
        });
      } else {
        // New cart item
        if (quantity > MAX_QUANTITY_PER_PRODUCT) {
          return res.status(400).json({
            message: `Cannot add more than ${MAX_QUANTITY_PER_PRODUCT} units of this product`,
          });
        }
        if (quantity > availableQuantity) {
          return res.status(400).json({
            message: `Cannot add more; only ${availableQuantity} units available`,
          });
        }

        const cartId = uuidv4();
        const insertQuery = 'INSERT INTO cart (cartId, userId, productId, quantity) VALUES (?, ?, ?, ?)';
        db.query(insertQuery, [cartId, userId, productId, quantity], (err, result) => {
          if (err) {
            console.error('Database error adding to cart:', err);
            return res.status(500).json({ message: 'Failed to add to cart' });
          }
          res.status(200).json({
            message: 'Product added to cart successfully',
            cartItem: { cartId, userId, productId, quantity },
          });
        });
      }
    });
  });
};

// Get cart items
const getCart = (req, res) => {
  const userId = req.userId;

  const sqlQuery = `
    SELECT c.cartId, c.productId, c.quantity, p.productName, p.price, p.images, p.Quantity as quantityAvailable
    FROM cart c
    JOIN product p ON c.productId = p.productId
    WHERE c.userId = ?
  `;
  db.query(sqlQuery, [userId], (err, result) => {
    if (err) {
      console.error('Database error fetching cart:', err);
      return res.status(500).json({ message: 'Failed to fetch cart items' });
    }
    res.status(200).json({ message: 'Cart retrieved successfully', items: result });
  });
};

// Update cart item
const updateCart = (req, res) => {
  const { cartId, quantity } = req.body;
  const MAX_QUANTITY_PER_PRODUCT = 6;

  if (!cartId || !quantity || quantity < 1) {
    return res.status(400).json({ message: 'Invalid cart ID or quantity' });
  }

  // Check cart item and product stock
  const cartQuery = `
    SELECT c.quantity, c.productId, p.quantity as quantityAvailable
    FROM cart c
    JOIN product p ON c.productId = p.productId
    WHERE c.cartId = ?
  `;
  db.query(cartQuery, [cartId], (err, cartResults) => {
    if (err) {
      console.error('Database error fetching cart item:', err);
      return res.status(500).json({ message: 'Server error' });
    }
    if (cartResults.length === 0) {
      return res.status(404).json({ message: 'Cart item not found' });
    }

    const availableQuantity = parseInt(cartResults[0].quantityAvailable, 10);

    if (quantity > MAX_QUANTITY_PER_PRODUCT) {
      return res.status(400).json({
        message: `Cannot set more than ${MAX_QUANTITY_PER_PRODUCT} units of this product`,
      });
    }
    if (quantity > availableQuantity) {
      return res.status(400).json({
        message: `Cannot set more; only ${availableQuantity} units available`,
      });
    }

    const updateQuery = 'UPDATE cart SET quantity = ? WHERE cartId = ?';
    db.query(updateQuery, [quantity, cartId], (err, result) => {
      if (err) {
        console.error('Database error updating cart:', err);
        return res.status(500).json({ message: 'Failed to update cart item' });
      }
      res.status(200).json({ message: 'Cart item updated successfully' });
    });
  });
};

// Remove from cart
const removeFromCart = (req, res) => {
  const { cartId } = req.body;

  if (!cartId) {
    return res.status(400).json({ message: 'Invalid cart ID' });
  }

  const sqlQuery = 'DELETE FROM cart WHERE cartId = ?';
  db.query(sqlQuery, [cartId], (err, result) => {
    if (err) {
      console.error('Database error removing from cart:', err);
      return res.status(500).json({ message: 'Failed to remove from cart' });
    }
    res.status(200).json({ message: 'Item removed from cart successfully' });
  });
};

// Clear cart
const clearCart = (req, res) => {
  const userId = req.userId;

  const sqlQuery = 'DELETE FROM cart WHERE userId = ?';
  db.query(sqlQuery, [userId], (err, result) => {
    if (err) {
      console.error('Database error clearing cart:', err);
      return res.status(500).json({ message: 'Failed to clear cart' });
    }
    res.status(200).json({ message: 'Cart cleared successfully' });
  });
};

module.exports = {
  verifyToken,
  addToCart,
  getCart,
  updateCart,
  removeFromCart,
  clearCart,
};







































// const db = require('../../Models/db');
// const jwt = require('jsonwebtoken');
// const { v4: uuidv4 } = require('uuid');

// // Middleware to verify JWT token
// const verifyToken = (req, res, next) => {
//   const token = req.headers.authorization?.split(' ')[1];
//   if (!token) {
//     console.error('No token provided');
//     return res.status(401).json({ message: 'Unauthorized' });
//   }

// //   console.log('JWT_SECRET in verifyToken:', process.env.JWT_SECRET);
//   jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
//     if (err) {
//       console.error('Token verification error:', err);
//       return res.status(401).json({ message: 'Invalid token' });
//     }
//     // console.log('Decoded token:', decoded);
//     if (!decoded.user_id) {
//       console.error('Token missing user_id:', decoded);
//       return res.status(401).json({ message: 'Invalid token payload' });
//     }
//     req.userId = decoded.user_id;
//     next();
//   });
// };

// // Add to cart
// const addToCart = (req, res) => {
//   const { productId, quantity } = req.body;
//   const userId = req.userId;
//   const cartId = uuidv4();

//   if (!productId || !quantity || quantity < 1) {
//     return res.status(400).json({ message: 'Invalid product ID or quantity' });
//   }

//   const sqlQuery = 'INSERT INTO cart (cartId, userId, productId, quantity) VALUES (?, ?, ?, ?)';
//   db.query(sqlQuery, [cartId, userId, productId, quantity], (err, result) => {
//     if (err) {
//       console.log('Database error:', err);
//       return res.status(500).json({ message: 'Failed to add to cart', error: err.message });
//     } else {
//       res.send({ message: 'Added to cart successfully', cartItem: { cartId, userId, productId, quantity } });
//     }
//   });
// };

// // Get cart items
// const getCart = (req, res) => {
//   const userId = req.userId;

//   const sqlQuery = `
//     SELECT c.cartId, c.productId, c.quantity, p.productName, p.price, p.images
//     FROM cart c
//     JOIN product p ON c.productId = p.productId
//     WHERE c.userId = ?
//   `;
//   db.query(sqlQuery, [userId], (err, result) => {
//     if (err) {
//       console.log('Database error:', err);
//       return res.status(500).json({ message: 'Failed to fetch cart items' });
//     } else {
//       res.send({ message: 'Cart retrieved successfully', items: result });
//     }
//   });
// };

// // Update cart item
// const updateCart = (req, res) => {
//   const { cartId, quantity } = req.body;

//   if (!cartId || !quantity || quantity < 1) {
//     return res.status(400).json({ message: 'Invalid cart ID or quantity' });
//   }

//   const sqlQuery = 'UPDATE cart SET quantity = ? WHERE cartId = ?';
//   db.query(sqlQuery, [quantity, cartId], (err, result) => {
//     if (err) {
//       console.log('Database error:', err);
//       return res.status(500).json({ message: 'Failed to update cart item' });
//     } else {
//       res.send({ message: 'Cart item updated successfully' });
//     }
//   });
// };

// // Remove from cart
// const removeFromCart = (req, res) => {
//   const { cartId } = req.body;

//   if (!cartId) {
//     return res.status(400).json({ message: 'Invalid cart ID' });
//   }

//   const sqlQuery = 'DELETE FROM cart WHERE cartId = ?';
//   db.query(sqlQuery, [cartId], (err, result) => {
//     if (err) {
//       console.log('Database error:', err);
//       return res.status(500).json({ message: 'Failed to remove from cart' });
//     } else {
//       res.send({ message: 'Item removed from cart successfully' });
//     }
//   });
// };

// // Clear cart
// const clearCart = (req, res) => {
//   const userId = req.userId;

//   const sqlQuery = 'DELETE FROM cart WHERE userId = ?';
//   db.query(sqlQuery, [userId], (err, result) => {
//     if (err) {
//       console.log('Database error:', err);
//       return res.status(500).json({ message: 'Failed to clear cart', error: err.message });
//     } else {
//       res.send({ message: 'Cart cleared successfully' });
//     }
//   });
// };

// module.exports = {
//   verifyToken,
//   addToCart,
//   getCart,
//   updateCart,
//   removeFromCart,
//   clearCart,
// };