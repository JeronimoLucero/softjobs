
require('dotenv').config(); 

module.exports = {
  dbConfig: {
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
  },
  jwtSecret: process.env.JWT_SECRET, 
};
