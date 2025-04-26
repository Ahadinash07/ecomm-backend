const express = require('express');
const { addToCart, getCart, updateCart, removeFromCart, clearCart, verifyToken } = require('../../Controllers/CartController/CartController');

const CartRoute = express.Router();

CartRoute.post('/add', verifyToken, addToCart);
CartRoute.get('/', verifyToken, getCart);
CartRoute.put('/update', verifyToken, updateCart);
CartRoute.delete('/remove', verifyToken, removeFromCart);
CartRoute.delete('/clear', verifyToken, clearCart);

module.exports = CartRoute;