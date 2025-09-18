const { DataTypes, Model  } = require('sequelize');
const sequelize = require('./dbms');

// Member model
const Member = sequelize.define('Member', {
  MemberID: { type: DataTypes.INTEGER, primaryKey: true },
  Owner: { type: DataTypes.INTEGER, allowNull: false },
  DeviceType: { type: DataTypes.SMALLINT, allowNull: false },
  Username: { type: DataTypes.STRING(80), allowNull: false },
  Password: { type: DataTypes.STRING(200), allowNull: false },
  MemberName: { type: DataTypes.STRING(100), allowNull: true },
  Email: { type: DataTypes.STRING(50), allowNull: true },
  MobilePhone: { type: DataTypes.STRING(50), allowNull: true },
  Img: { type: DataTypes.TEXT, allowNull: true },
  Created: { type: DataTypes.DATE, allowNull: false },
  FriendAddToken: { type: DataTypes.STRING(64), allowNull: true },
  FriendAddExpire: { type: DataTypes.DATE, allowNull: true },
  IsFriendAddUnlimit: { type: DataTypes.BOOLEAN, allowNull: false },
  HistoryLimit: { type: DataTypes.INTEGER, allowNull: true },
  Description: { type: DataTypes.STRING(255), allowNull: true },
}, {
  tableName: 'Member',
  timestamps: false,
});
/*

// Devices model
const Devices = sequelize.define('Devices', {
  MemberID: { type: DataTypes.INTEGER, allowNull: false },
  DeviceID: { type: DataTypes.SMALLINT, primaryKey: true },
  DeviceStyleID: { type: DataTypes.SMALLINT, allowNull: false },
  DeviceName: { type: DataTypes.STRING(32), allowNull: true },
  DeviceStatusText: { type: DataTypes.STRING(50), allowNull: true },
}, {
  tableName: 'Devices',
  timestamps: false,
});


// DeviceStyle model
const DeviceStyle = sequelize.define('DeviceStyle', {
  DeviceStyleID: { type: DataTypes.SMALLINT, primaryKey: true },
  Name: { type: DataTypes.STRING(50), allowNull: false },
}, {
  tableName: 'DeviceStyle',
  timestamps: false,
});


// DeviceControl model
const DeviceControl = sequelize.define('DeviceControl', {
  MemberID: { type: DataTypes.INTEGER, allowNull: false },
  DeviceID: { type: DataTypes.SMALLINT, allowNull: false },
  ControlID: { type: DataTypes.SMALLINT, primaryKey: true },
  ConTypeID: { type: DataTypes.TINYINT, allowNull: false },
  IsCustomIMG: { type: DataTypes.BOOLEAN, allowNull: false },
  Label: { type: DataTypes.STRING(50), allowNull: true },
  LastValue: { type: DataTypes.FLOAT, allowNull: true },
  Created: { type: DataTypes.DATE, allowNull: false },
}, {
  tableName: 'DevicetControl',
  timestamps: false,
});

// FriendRight model
const FriendRight = sequelize.define('FriendRight', {
  FRID: { type: DataTypes.INTEGER, primaryKey: true, allowNull: false },
  Name: { type: DataTypes.STRING(15), allowNull: false },
  Description: { type: DataTypes.STRING(255), allowNull: true },
}, {
  tableName: 'FriendRight',
  timestamps: false,
});

// Friends model
const Friends = sequelize.define('Friends', {
  FRID: { type: DataTypes.INTEGER, primaryKey: true, allowNull: false },
  Name: { type: DataTypes.STRING(15), allowNull: false },
  Description: { type: DataTypes.STRING(255), allowNull: true },
}, {
  tableName: 'Friends',
  timestamps: false,
});
*/

module.exports = { Member };
