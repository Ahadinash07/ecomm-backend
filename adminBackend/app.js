const express = require('express');
const env = require('dotenv');
const cors = require('cors');
const adminUserRegistrationRoute = require('./Routes/adminUserRegistrationRoute/adminUserRegistrationRoute');
const AdminRoleRoute = require('./Routes/AdminRoleRoute/AdminRoleRoute');
const AdminRoleAssignRoute = require('./Routes/AdminRoleAssignRoute/AdminRoleAssignRoute');
const AdminUserProfileRoute = require('./Routes/AdminUserProfileRoutes/AdminUserProfileRoute');
const CategoryRoute = require('./Routes/CategoryRoutes/CategoryRoutes');
const SubCategoryRoute = require('./Routes/SubCategoryRoutes/SubCategoryRoutes');
const RetailerregisterRoute = require('./Routes/RetailerRegistationRoute/RetailerRegistationRoute');
const RetailerProfileRoute = require('./Routes/RetailerProfileRoute/RetailerProfileRoute');
const ProductRoute = require('./Routes/ProductRoute/ProductRoute');
const ProductDescriptionRoute = require('./Routes/ProductDescriptionRoute/ProductDescriptionRoute');
const UserRoute = require('./Routes/UserRoute/UserRoute');
const CartRoute = require('./Routes/CartRoute/CartRoute');
const OrderRoute = require('./Routes/OrderRoutes/OrderRoutes');
const AddressRoute = require('./Routes/AddressRoute/AddressRoute');

const app = express();
env.config();
app.use(cors({
    // origin: ['http://localhost:5173', 'https://ecomm-frontend-mu.vercel.app'],
    origin: ['http://localhost:5173', 'https://e-shop-client.netlify.app'],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
}));
app.use(express.json());

const PORT = process.env.SERVER_PORT;

app.use('/', adminUserRegistrationRoute);

app.use('/', AdminRoleRoute);

app.use('/', AdminRoleAssignRoute);

app.use('/', AdminUserProfileRoute);

app.use('/api', CategoryRoute);

app.use('/api', SubCategoryRoute);

app.use('/', RetailerregisterRoute);

app.use('/', RetailerProfileRoute);

app.use('/api/products', ProductRoute);

app.use('/', ProductDescriptionRoute);

app.use('/api/auth', UserRoute);

app.use('/api/cart', CartRoute);

app.use('/api/orders', OrderRoute);

app.use('/api/addresses', AddressRoute);

if (require.main === module) {
    app.listen(PORT, () => console.log(`http://localhost:${PORT}`));
};


module.exports = app;