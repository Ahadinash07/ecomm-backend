const db = require('../../Models/db');
const jwt = require('jsonwebtoken');

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

// Add a new address
const addAddress = (req, res) => {
  const { address_line, city, state, country, zip_code, phone, is_default } = req.body;
  const userId = req.userId;

  console.log('Received addAddress request:', { userId, address_line, city, state, country, zip_code, phone, is_default });

  // Validate required fields
  if (!address_line || !city || !state || !country || !zip_code || !phone) {
    console.error('Missing required fields:', req.body);
    return res.status(400).json({ message: 'All address fields are required' });
  }

  // Validate field lengths
  if (city.length > 50) {
    return res.status(400).json({ message: 'City must be 50 characters or less' });
  }
  if (state.length > 50) {
    return res.status(400).json({ message: 'State must be 50 characters or less' });
  }
  if (country.length > 50) {
    return res.status(400).json({ message: 'Country must be 50 characters or less' });
  }
  if (zip_code.length > 20) {
    return res.status(400).json({ message: 'Zip code must be 20 characters or less' });
  }
  if (phone.length > 20) {
    return res.status(400).json({ message: 'Phone number must be 20 characters or less' });
  }

  const insertAddress = () => {
    const query = `
      INSERT INTO addresses (user_id, address_line, city, state, country, zip_code, phone, is_default)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;
    db.query(query, [userId, address_line, city, state, country, zip_code, phone, is_default ? 1 : 0], (err, result) => {
      if (err) {
        console.error('Database error adding address:', err);
        return res.status(500).json({ message: 'Failed to add address', error: err.message });
      }
      console.log('Address added successfully');
      res.status(201).json({ message: 'Address added successfully' });
    });
  };

  if (is_default) {
    const unsetDefaultQuery = 'UPDATE addresses SET is_default = 0 WHERE user_id = ? AND is_default = 1';
    db.query(unsetDefaultQuery, [userId], (err) => {
      if (err) {
        console.error('Database error unsetting default address:', err);
        return res.status(500).json({ message: 'Failed to update default address', error: err.message });
      }
      insertAddress();
    });
  } else {
    insertAddress();
  }
};

// Get all addresses for a user
const getAddresses = (req, res) => {
  const userId = req.userId;

  const query = 'SELECT * FROM addresses WHERE user_id = ?';
  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Database error fetching addresses:', err);
      return res.status(500).json({ message: 'Failed to fetch addresses', error: err.message });
    }
    res.status(200).json({ message: 'Addresses retrieved successfully', addresses: results });
  });
};

// Update an address
const updateAddress = (req, res) => {
  const { address_id, address_line, city, state, country, zip_code, phone, is_default } = req.body;
  const userId = req.userId;

  if (!address_id || !address_line || !city || !state || !country || !zip_code || !phone) {
    return res.status(400).json({ message: 'All address fields are required' });
  }

  // Validate field lengths
  if (city.length > 50) {
    return res.status(400).json({ message: 'City must be 50 characters or less' });
  }
  if (state.length > 50) {
    return res.status(400).json({ message: 'State must be 50 characters or less' });
  }
  if (country.length > 50) {
    return res.status(400).json({ message: 'Country must be 50 characters or less' });
  }
  if (zip_code.length > 20) {
    return res.status(400).json({ message: 'Zip code must be 20 characters or less' });
  }
  if (phone.length > 20) {
    return res.status(400).json({ message: 'Phone number must be 20 characters or less' });
  }

  // Check if address belongs to user
  const checkQuery = 'SELECT * FROM addresses WHERE address_id = ? AND user_id = ?';
  db.query(checkQuery, [address_id, userId], (err, results) => {
    if (err) {
      console.error('Database error checking address:', err);
      return res.status(500).json({ message: 'Server error', error: err.message });
    }
    if (results.length === 0) {
      return res.status(404).json({ message: 'Address not found' });
    }

    const updateAddress = () => {
      const query = `
        UPDATE addresses
        SET address_line = ?, city = ?, state = ?, country = ?, zip_code = ?, phone = ?, is_default = ?
        WHERE address_id = ?
      `;
      db.query(query, [address_line, city, state, country, zip_code, phone, is_default ? 1 : 0, address_id], (err) => {
        if (err) {
          console.error('Database error updating address:', err);
          return res.status(500).json({ message: 'Failed to update address', error: err.message });
        }
        res.status(200).json({ message: 'Address updated successfully' });
      });
    };

    if (is_default) {
      const unsetDefaultQuery = 'UPDATE addresses SET is_default = 0 WHERE user_id = ? AND is_default = 1';
      db.query(unsetDefaultQuery, [userId], (err) => {
        if (err) {
          console.error('Database error unsetting default address:', err);
          return res.status(500).json({ message: 'Failed to update default address', error: err.message });
        }
        updateAddress();
      });
    } else {
      updateAddress();
    }
  });
};

// Delete an address
const deleteAddress = (req, res) => {
  const { address_id } = req.body;
  const userId = req.userId;

  if (!address_id) {
    return res.status(400).json({ message: 'Address ID is required' });
  }

  const query = 'DELETE FROM addresses WHERE address_id = ? AND user_id = ?';
  db.query(query, [address_id, userId], (err, result) => {
    if (err) {
      console.error('Database error deleting address:', err);
      return res.status(500).json({ message: 'Failed to delete address', error: err.message });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Address not found' });
    }
    res.status(200).json({ message: 'Address deleted successfully' });
  });
};

module.exports = {
  verifyToken,
  addAddress,
  getAddresses,
  updateAddress,
  deleteAddress,
};
