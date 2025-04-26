const express = require("express");
const { createOrder, verifyPayment, getOrders, verifyToken } = require("../../Controllers/OrderController/OrderController");
const OrderRoute = express.Router();

// Apply verifyToken middleware to all order routes
OrderRoute.use(verifyToken);

OrderRoute.post('/create', createOrder);
OrderRoute.post('/verify-payment', verifyPayment);
OrderRoute.get('/', getOrders);

module.exports = OrderRoute;