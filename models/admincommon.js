const admincommand = {
  UnknowCommand: 0,
  Login: 1,
  Redirect: 7,
  Logout: 2,
  DeviceControl: 3,
  DeviceControlByteArray: 30,
  DeviceUpdateValue: 31,
  DeviceUpdateValueAddHistotory: 35,
  DeviceUpdateValueCombo: 33,
  GetFriendInformation: 32,
  FriendInformation: 34,
  DeviceControlCustom: 4,
  DeviceControlCombo: 5,
  FriendStatus: 9,
  Ping: 91,
  Pong: 92,
  ServerMessage: 90,
  CommandReject: 99,
  //Admin command
  GetClient: 101,
  ClientConnect: 102,
  ClientDisconnect: 103,
  ClientUpdateInfo: 104,
  Log: 105,

  Connect: 200,
  Disconnect: 201,
  Error: 999,
};

module.exports = { admincommand };
