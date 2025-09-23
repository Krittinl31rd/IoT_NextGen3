const { Sequelize } = require("sequelize");
const sequelize = require("./dbms");

async function query(_sql) {
  try {
    const res = await sequelize.query(_sql, {
      type: Sequelize.QueryTypes.SELECT,
    });
    //console.log('query', res);
    return { response: res };
  } catch (error) {
    console.log("Error executing query:", error);
    console.error("Error executing query:", error);
    return { error: error };
  }
}
async function querys(_sql, _param) {
  try {
    const res = await sequelize.query(_sql, {
      replacements: _param,
      type: Sequelize.QueryTypes.SELECT,
    });
    //console.log('query param', res);
    return { response: res };
  } catch (error) {
    console.log("Error executing query:", error);
    console.error("Error executing query:", error);
    return { error: error };
  }
}

async function excute(_sql) {
  try {
    const res = await sequelize.query(_sql);
    //console.log('excute ', res);
    return { response: res };
  } catch (error) {
    console.error("Error executing query:", error);
    return { error: error };
  }
}

async function excutes(_sql, _param) {
  try {
    const res = await sequelize.query(_sql, {
      replacements: _param,
    });
    //console.log('excute param', res);
    return { response: res };
  } catch (error) {
    console.error("Error executing query:", error);
    return { error: error };
  }
}

// async function excutes(_sql, _param) {
//   try {
//     const [result, metadata] = await sequelize.query(_sql, {
//       replacements: _param,
//     });

//     return { result, metadata };
//   } catch (error) {
//     console.error("Error executing query:", error);
//     return { error };
//   }
// }

module.exports = { query, querys, excute, excutes };
