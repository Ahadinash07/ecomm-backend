const db = require('../../Models/db');
const Razorpay = require('razorpay');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  console.log('verifyToken: Checking token', { token }); // Debug log
  
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
    
    console.log('Token verified:', decoded); // Debug log
    req.userId = decoded.user_id; // Set userId consistently
    next();
  });
};

const createOrder = async (req, res) => {
  const { address_id, payment_method } = req.body;
  const userId = req.userId; // Get from verified token

  console.log('Creating order with:', { address_id, payment_method, userId });

  if (!address_id || !payment_method) {
    console.error('Missing required fields');
    return res.status(400).json({ message: 'Address ID and payment method are required' });
  }

  if (!['Razorpay', 'COD'].includes(payment_method)) {
    console.error('Invalid payment method:', payment_method);
    return res.status(400).json({ message: 'Invalid payment method. Must be "Razorpay" or "COD"' });
  }

  try {
    // 1. Fetch cart items for this user
    const cartQuery = `
      SELECT c.cartId, c.productId, c.quantity, p.productName, p.price, p.quantity as quantityAvailable
      FROM cart c
      JOIN product p ON c.productId = p.productId
      WHERE c.userId = ?
    `;
    
    db.query(cartQuery, [userId], async (err, cartItems) => {
      if (err) {
        console.error('Database error fetching cart:', err);
        return res.status(500).json({ message: 'Server error' });
      }
      
      if (cartItems.length === 0) {
        console.error('Cart is empty for user:', userId);
        return res.status(400).json({ message: 'Cart is empty' });
      }

      // 2. Validate address belongs to user
      const addressQuery = 'SELECT * FROM addresses WHERE address_id = ? AND user_id = ?';
      db.query(addressQuery, [address_id, userId], async (err, addressResults) => {
        if (err) {
          console.error('Database error fetching address:', err);
          return res.status(500).json({ message: 'Server error' });
        }
        
        if (addressResults.length === 0) {
          console.error('Address not found or does not belong to user:', { address_id, userId });
          return res.status(404).json({ message: 'Address not found' });
        }

        // 3. Validate stock availability
        for (const item of cartItems) {
          if (item.quantity > item.quantityAvailable) {
            console.error('Insufficient stock:', {
              product: item.productName,
              requested: item.quantity,
              available: item.quantityAvailable
            });
            return res.status(400).json({
              message: `Not enough stock for ${item.productName}. Available: ${item.quantityAvailable}`,
            });
          }
        }

        // 4. Calculate total amount
        const totalAmount = cartItems.reduce((sum, item) => sum + item.price * item.quantity, 0);

        const orderId = uuidv4();
        let razorpayOrderId = null;

        if (payment_method === 'Razorpay') {
          try {
            // Create Razorpay order
            const razorpayOrder = await razorpay.orders.create({
              amount: totalAmount * 100,
              currency: 'INR',
              receipt: orderId,
            });
            razorpayOrderId = razorpayOrder.id;
          } catch (razorpayError) {
            console.error('Razorpay order creation failed:', razorpayError);
            return res.status(500).json({ message: 'Failed to create Razorpay order' });
          }
        }

        // 5. Create order in database
        const orderQuery = `
          INSERT INTO orders (order_id, user_id, address_id, total_amount, payment_method, razorpay_order_id, payment_status, order_status)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `;
        
        db.query(
          orderQuery,
          [orderId, userId, address_id, totalAmount, payment_method, razorpayOrderId, 'Pending', 'Pending'],
          (err) => {
            if (err) {
              console.error('Database error creating order:', err);
              return res.status(500).json({ message: 'Failed to create order' });
            }

            // 6. Create order items
            const orderItemsQuery = `
              INSERT INTO order_items (order_item_id, order_id, product_id, quantity, price)
              VALUES ?
            `;
            const orderItemsValues = cartItems.map((item) => [
              uuidv4(),
              orderId,
              item.productId,
              item.quantity,
              item.price,
            ]);
            
            db.query(orderItemsQuery, [orderItemsValues], (err) => {
              if (err) {
                console.error('Database error inserting order items:', err);
                return res.status(500).json({ message: 'Failed to create order items' });
              }

              // 7. Update product stock
              const updateStockQuery = 'UPDATE product SET quantity = quantity - ? WHERE productId = ?';
              cartItems.forEach((item) => {
                db.query(updateStockQuery, [item.quantity, item.productId], (err) => {
                  if (err) {
                    console.error('Database error updating stock:', err);
                  }
                });
              });

              // 8. Clear cart
              const clearCartQuery = 'DELETE FROM cart WHERE userId = ?';
              db.query(clearCartQuery, [userId], (err) => {
                if (err) {
                  console.error('Database error clearing cart:', err);
                }
                
                res.status(201).json({
                  message: 'Order created successfully',
                  order_id: orderId,
                  razorpay_order_id: razorpayOrderId,
                  amount: totalAmount,
                  currency: 'INR',
                });
              });
            });
          }
        );
      });
    });
  } catch (error) {
    console.error('Error creating order:', error);
    res.status(500).json({ message: 'Failed to create order' });
  }
};

const verifyPayment = (req, res) => {
  const { order_id, razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
  const userId = req.userId;

  if (!order_id || !razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
    return res.status(400).json({ message: 'Invalid payment details' });
  }

  // Verify signature
  const generatedSignature = crypto
    .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
    .update(`${razorpay_order_id}|${razorpay_payment_id}`)
    .digest('hex');

  if (generatedSignature !== razorpay_signature) {
    return res.status(400).json({ message: 'Invalid payment signature' });
  }

  // Update order
  const query = `
    UPDATE orders
    SET payment_status = 'Completed', 
        razorpay_payment_id = ?, 
        razorpay_signature = ?, 
        order_status = 'Confirmed'
    WHERE order_id = ? AND user_id = ?
  `;
  
  db.query(query, [razorpay_payment_id, razorpay_signature, order_id, userId], (err, result) => {
    if (err) {
      console.error('Database error updating payment:', err);
      return res.status(500).json({ message: 'Failed to verify payment' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Order not found' });
    }
    res.status(200).json({ message: 'Payment verified successfully' });
  });
};

const getOrders = (req, res) => {
  const userId = req.userId;

  const query = `
    SELECT o.order_id, o.total_amount, o.payment_method, o.payment_status, o.order_status, o.created_at,
           a.address_line, a.city, a.state, a.country, a.zip_code, a.phone
    FROM orders o
    JOIN addresses a ON o.address_id = a.address_id
    WHERE o.user_id = ?
    ORDER BY o.created_at DESC
  `;
  
  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Database error fetching orders:', err);
      return res.status(500).json({ message: 'Failed to fetch orders' });
    }
    res.status(200).json({ 
      message: 'Orders retrieved successfully', 
      orders: results 
    });
  });
};

module.exports = {
  verifyToken,
  createOrder,
  verifyPayment,
  getOrders,
};