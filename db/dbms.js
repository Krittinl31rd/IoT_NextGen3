const { Sequelize } = require("sequelize");

// Create a connection to the database
/*const sequelize = new Sequelize('IOTServer', 'sa', 'Archi_123456', {
  host: 'localhost',
  dialect: 'mssql', // Specify MSSQL as the dialect
  logging: false,  // Disable logging if not needed
  dialectOptions: {
    options: {
      encrypt: true, // Use encryption
    }
  }
});*/

const sequelizeConfig = {
  host: process.env.DB_Host || "localhost", // Use environment variable for host
  dialect: "mssql", // Change to MSSQL as the dialect
  logging: false, // Disable logging if not needed
  dialectOptions: {
    port: Number(process.env.DB_Port),
  },
};

// Conditionally add MSSQL-specific options
if (process.env.DB_Type === "mssql") {
  sequelizeConfig.dialectOptions.options = {
    encrypt: true, // For secure connections (required for Azure SQL)
    trustServerCertificate: process.env.DB_TrustServerCert === "true", // To bypass SSL for self-signed certs
    port: Number(process.env.DB_Port),
  };
}

// Initialize Sequelize
const sequelize = new Sequelize(
  process.env.DB_Name,
  process.env.DB_User,
  process.env.DB_Pass,
  sequelizeConfig
);
module.exports = sequelize;
