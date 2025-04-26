const express = require("express");
const { addAddress, getAddresses, updateAddress, deleteAddress, verifyToken } = require("../../Controllers/AddressController/AddressController");
const AddressRoute = express.Router();


AddressRoute.post('/add', verifyToken, addAddress);
AddressRoute.get('/', verifyToken, getAddresses);
AddressRoute.put('/update', verifyToken, updateAddress);
AddressRoute.delete('/delete', verifyToken, deleteAddress);

module.exports = AddressRoute;