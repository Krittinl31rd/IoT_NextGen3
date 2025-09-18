const command =
{
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

    Configuration: 301
}

const loginStatus =
{
    Success: 0,
    WrongUsernameOrPassword: 1,
    Expired: 2,
    NotSuccess: 99
}

const onDeviceControlType =
{
    Undefind: -1,
    DeviceStatus: 0,
    ControlDevice: 1
}
const friendRight =
{
    NotFriend: -1,
    Normal: 0,//control
    DeviceAdmin: 1,
    DeviceControl: 2,
    DeviceMonitor: 3
}

const deviceType =
{
    Undefind: -1,
    User: 1,
    Device: 2,
    DeviceByteArray: 3
}

const deviceControlType =
{
    OnOff: 0,
    Slider: 1,
    Volume: 2
}

const connectionStatusType =
{
    Connected: 1,
    Disconnected: 2,
    ConnectionTerminated: 3,
    ConnectionError: 4,
    NotConnect: 5,
    AlreadyConnect: 6
}

const disconnectTypeEnum = Object.freeze({
    NA: 0,
    ClientDisconnect: 1,
    Kick: 2
});


module.exports = { command, loginStatus, onDeviceControlType, friendRight, deviceType, deviceControlType, connectionStatusType, disconnectTypeEnum };