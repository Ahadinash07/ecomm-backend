const mysql = require('mysql2');
require('dotenv').config();

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    port: 3306
});

// More robust connection handling
db.connect((err) => {
    if (err) {
        console.error('Database connection failed:', err.message);
        // Retry connection after delay if needed
        setTimeout(() => db.connect(), 5000); 
    } else {
        console.log("Successfully connected to database");
    }
});

// Handle connection errors after initial connect
db.on('error', (err) => {
    console.error('Database connection lost:', err.message);
    if (err.code === 'PROTOCOL_CONNECTION_LOST') {
        // Reconnect if connection drops
        db.connect(); 
    }
});

module.exports = db;


































// const mysql = require('mysql2');
// const env = require('dotenv');

// env.config();

// const db = mysql.createConnection({
//     user: process.env.DB_USER,
//     host: process.env.DB_HOST,
//     password: process.env.DB_PASS,
//     database: process.env.DB_NAME
// })

// db.connect((err) => {
//     if(err) 
//     console.log(err);
//     else
//     console.log("Database connected");
// });

// module.exports = db;