var createError = require("http-errors");
var express = require("express");
var path = require("path");
var cookieParser = require("cookie-parser");
var logger = require("morgan");
const bcrypt = require('bcrypt');
var indexRouter = require("./routes/index");
var usersRouter = require("./routes/users");
const { command, loginStatus, onDeviceControlType, friendRight, deviceType, deviceControlType, connectionStatusType, disconnectTypeEnum } = require("./models/common");

//const sql = require('mssql')
const { Member } = require('./db/models');
let { query, querys, excute, excutes } = require('./db/sql');

const fs = require("fs");
const https = require("http");
const WebSocket = require("ws");

var app = express();

// view engine setup
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(logger("dev"));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

app.use("/", indexRouter);
app.use("/users", usersRouter);

// catch 404 and forward to error handler
app.use(function (req, res, next) {
  next(createError(404));
});

// error handler
app.use(function (err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get("env") === "development" ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render("error");
});

////////////////////////////////////////////////////////////////////////////////////////

/**
 * Websocket
 */

// Create an HTTPS server
const serverOptions = {
  cert: fs.readFileSync("cert/cert.pem", "utf8"),
  key: fs.readFileSync("cert/key.pem", "utf8"),
};
var server = https.createServer(app);

// Create a WebSocket server bound to the HTTPS server
const wss = new WebSocket.Server({
  server: server,
  path: "/echo",
});

var wsClient = [];

wss.on("connection", function connection(ws) {
  wsClient.push(ws);
  ws.on("message", function incoming(message) {
    console.log("received: %s", message);
  });

  ws.on("close", function close() {
    console.log("disconnected");
  });

  ws.send("init message to client");
});

// Start the server on port 4000
server.listen(1231, function () {
  console.log("Server is listening on port 1231");
});
////////////////////////////////////////////////////////////////
const net = require("net");
const port = 9090;
const host = "127.0.0.1";

const tcpserver = net.createServer();
tcpserver.listen(port, host, () => {
  console.log("TCP Server is running on port " + port + ".");
});

let sockets = [];

tcpserver.on("connection", function (sock) {
  console.log("CONNECTED: " + sock.remoteAddress + ":" + sock.remotePort);
  let csock = {
    socket: sock,
    info: {
      id: 0,
      name: ''
    },
    islogin: false
  };
  sockets.push(csock);

  sock.on("data", function async(data) {
    //console.log("DATA " + sock.remoteAddress + ": " + data);
    //max 32965
    const buff = new Uint16Array(data);
    //console.log(buff);
    const { cmd, payload, length } = verifyPackage(buff);
    console.log(`verifyPackage cmd:${cmd}, length:${length}, payload:${payload}`);
    if (cmd == -1) {
      console.log(`Payload : ${payload}`);
    }
    else {
      if (cmd == command.Login) {//Login
        //01 33 01 00 7b 22 55 73 65 72 6e 61 6d 65 22 3a 22 68 61 6d 22 2c 22 50 61 73 73 77 6f 72 64 22 3a 22 31 32 33 34 35 36 22 2c 22 54 6f 6b 65 6e 22 3a 22 22 7d


        //{01}{7A}{01}{00}{7B}{22}{53}{75}{63}{63}{65}{73}{73}{22}{3A}{74}{72}{75}{65}{2C}{22}{4D}{65}{6D}{62}{65}{72}{49}{44}{22}{3A}{32}{2C}{22}{4E}{61}{6D}{65}{22}{3A}{22}{4E}{6F}{74}{74}{69}{6E}{67}{48}{61}{6D}{20}{53}{6D}{69}{74}{68}{20}{41}{6C}{6C}{79}{22}{2C}{22}{44}{65}{76}{69}{63}{65}{54}{79}{70}{65}{22}{3A}{31}{2C}{22}{53}{74}{61}{74}{75}{73}{22}{3A}{30}{2C}{22}{4D}{65}{73}{73}{61}{67}{65}{22}{3A}{22}{57}{65}{6C}{63}{6F}{6D}{65}{20}{74}{6F}{20}{49}{4F}{54}{20}{53}{65}{72}{76}{65}{72}{22}{7D}
        //{"Success":true,"MemberID":2,"Name":"NottingHam Smith Ally","DeviceType":1,"Status":0,"Message":"Welcome to IOT Server"}
        let jpayload = JSON.parse(payload);

        if (jpayload.Username) {
          (async () => {
            try {
              // Perform the query
              const member = await Member.findOne({
                where: {
                  Username: jpayload.Username, // Condition to match the Username field
                },
              });

              // Handle the case where no member is found
              if (member) {

                bcrypt.compare(jpayload.Password, member.Password, function (err, result) {
                  if (err) {
                    console.log(`Crypto.Error : ${err}`);
                  }
                  else {
                    console.log(`Password : ${result}`);
                    if (result == true) {
                      //console.log(`Login : ${sock.remoteAddress}:${sock.remotePort}`);
                      let p = {
                        Success: true,
                        MemberID: member.MemberID,
                        Name: `${member.MemberName}`,
                        DeviceType: member.DeviceType,
                        Status: loginStatus.Success,
                        Message: "Welcome to IOT Server"
                      };

                      csock.islogin = true;
                      //console.log(`sock : ${JSON.stringify(csock.info)}`);
                      csock.info.id = member.MemberID;
                      csock.info.name = member.MemberName;
                      //console.log(`sock : ${JSON.stringify(csock.info)}`);

                      //let soc = sockets.find(item => item.socket === sock);
                      //console.log(`sock : ${JSON.stringify(soc.info)}`);


                      const report = sendPackage(command.Login, JSON.stringify(p));
                      sock.write(report);
                    }
                    else {
                      //{"Success":false,"MemberID":0,"Name":"","DeviceType":0,"Status":1,"Message":"password is invalid"}
                      let p = {
                        Success: false,
                        MemberID: 0,
                        Name: "",
                        DeviceType: 0,
                        Status: loginStatus.WrongUsernameOrPassword,
                        Message: "password is invalid"
                      };
                      const report = sendPackage(command.Login, JSON.stringify(p));
                      sock.write(report);
                    }
                  }
                });

                //console.log(`Member found: ${JSON.stringify(member)}`);
              } else {
                //{"Success":false,"MemberID":0,"Name":"","DeviceType":0,"Status":1,"Message":"password is invalid"}
                let p = {
                  Success: false,
                  MemberID: 0,
                  Name: "",
                  DeviceType: 0,
                  Status: loginStatus.WrongUsernameOrPassword,
                  Message: "Username not found."
                };
                const report = sendPackage(command.Login, JSON.stringify(p));
                sock.write(report);
                //console.log(`No member found with username: ${jpayload.Username}`);
              }
            } catch (error) {
              console.error(`Error fetching member: ${error.message}`);
            }
          })(); // Invoke the async function
        } else {
          console.log("jpayload.Username is undefined or null");
        }




      }
      else if (cmd == command.Logout) {//Logout
        if (csock.islogin == false) {
          //Reject command
          let p = {
            Status: 0,
            Message: 'Command reject',
          };
          const report = sendPackage(command.CommandReject, JSON.stringify(p));
          sock.write(report);
        }
        else {
          console.log(`Logout : ${sock.remoteAddress}:${sock.remotePort}`);
        }

      }
      else if (cmd == command.DeviceControl) {//Control
        if (csock.islogin == false) {
          //Reject command
          let p = {
            Status: 0,
            Message: 'Command reject',
          };
          const report = sendPackage(command.CommandReject, JSON.stringify(p));
          sock.write(report);
        }
        else {
          //01 36 03 00 7B 22 56 22 3A 31 2E 30 2C 22 4D 65 6D 62 65 72 22 3A 31 30 31 38 2C 22 44 65 76 69 63 65 22 3A 33 30 30 31 2C 22 43 74 72 6C 22 3A 31 2C 22 52 22 3A 30 7D         
          //[Response]
          //z{"Success":false,"Message":"Member is not online, Member is not online","Member":3,"Device":3001,"Ctrl":1,"V":0.0,"R":0}
          //z{"Success":true,"Message":"Success","Member":3,"Device":3001,"Ctrl":1,"V":0.0,"R":0}
          //[Request]
          //cmd:3, length:51, payload:{"V":0.0,"Member":3,"Device":3001,"Ctrl":1,"R":0}
          //{"V":1.0,"Member":1018,"Device":3001,"Ctrl":1,"R":0}
          //8{"Member":2343,"Device":7101,"Ctrl":23,"V":57.2,"R":0}

          //let { V, Member, Device, Ctrl, R } = JSON.parse(payload);
          console.log(`control : ${payload}`);

          //let payloadString = payload.toString('utf-8');

          let jpayload = JSON.parse(payload); // Parse the JSON string
          let p = {
            Member: jpayload.Member,
            Device: jpayload.Device,
            Ctrl: jpayload.Ctrl,
            V: jpayload.V,
            R: jpayload.R
          };
          const report = sendPackage(command.DeviceUpdateValue, JSON.stringify(p));
          sock.write(report);
        }

      }
      /* (For client)
      else if (cmd == command.FriendStatus) { // gateway online status

      }
      else if (cmd == command.FriendInformation) { // gateway information

      }*/
      else if (cmd == command.GetFriendInformation) { // get information
        if (csock.islogin == false) {
          //Reject command
          let p = {
            Status: 0,
            Message: 'Command reject',
          };
          console.log(p);
          const report = sendPackage(command.CommandReject, JSON.stringify(p));
          sock.write(report);
        }
        else {
          //let soc = sockets.find(item => item.socket === sock);
          //let mid = Object.keys(gitem)

          console.log('MemberID:', csock.info.id);

          let gateway = {};

          //Get gateway
          querys('SELECT Friends.MemberID as MemberID, Friends.Friend as Friend, Friends.FRID as FRID, Member.DeviceType as DeviceType, Member.MemberName as MemberName, Member.Img as Img FROM Friends inner join Member on Friends.Friend = Member.MemberID WHERE Friends.MemberID = :mid', { mid: csock.info.id })
            .then((mem) => {
              //console.log('Query result:', mem);
              mem.response.forEach(member => {
                /*let gatewayItem = {
                  [member.Friend.toString()]: {
                    Status: 0,
                    Img: member.Img,
                    Name: member.MemberName,
                    DeviceType: member.DeviceType,
                    Device: {}
                  }
                };*/
                //gateway.push(gatewayItem);
                gateway[member.Friend.toString()] = {};
                gateway[member.Friend.toString()] = {
                  Status: 0,
                  Img: member.Img,
                  Name: member.MemberName,
                  DeviceType: member.DeviceType,
                  Device: {}
                }

                /*gateway[member.Friend.toString()].Status = 0;
                gateway[member.Friend.toString()].Img = member.Img;
                gateway[member.Friend.toString()].Name = member.MemberName;
                gateway[member.Friend.toString()].DeviceType = member.DeviceType;
                gateway[member.Friend.toString()].Device = {};*/

                //Get Device
                gateway[member.Friend.toString()].Device = {};
                querys('SELECT * FROM Devices WHERE MemberID = :mid', { mid: member.Friend })
                  .then((dev) => {
                    //console.log('Query result:', dev);
                    dev.response.forEach(device => {
                      /*let devieItem = {
                        [device.DeviceID.toString()]: {
                          DeviceName: device.DeviceName,
                          DeviceStyleID: device.DeviceStyleID,
                          //RoomID: 1,
                          Control: {}
                        }
                      };*/
                      //console.log(`device : ${device.DeviceName}`);
                      //gatewayItem[member.Friend.toString()].Device.push(devieItem);

                      gateway[member.Friend.toString()].Device[device.DeviceID.toString()] = {
                        DeviceName: device.DeviceName,
                        DeviceStyleID: device.DeviceStyleID,
                        //RoomID: 1,
                        Control: {}
                      };
                      /*gatewayItem[member.Friend.toString()].Device[device.DeviceID.toString()].DeviceName = device.DeviceName;
                      gatewayItem[member.Friend.toString()].Device[device.DeviceID.toString()].DeviceStyleID = device.DeviceStyleID;
                      gatewayItem[member.Friend.toString()].Device[device.DeviceID.toString()].Control = {};*/

                      //Get Control
                      gateway[member.Friend.toString()].Device[device.DeviceID.toString()].Control = {};
                      querys('SELECT * FROM DevicetControl WHERE MemberID = :mid and DeviceID = :did', { mid: member.Friend, did: device.DeviceID })
                        .then((ctrl) => {
                          //console.log('Query result:', ctrl);
                          ctrl.response.forEach(control => {
                            /*let controlItem = {
                              [control.ControlID.toString()]: {
                                ControlType: control.ConTypeID,
                                Label: control.Label,
                                Value: control.LastValue
                              }
                            };*/

                            //gatewayItem[member.Friend.toString()].Device[device.DeviceID.toString()].Control.push(controlItem);
                            //devieItem[device.DeviceID.toString()].Control.push(controlItem);

                            gateway[member.Friend.toString()].Device[device.DeviceID.toString()].Control = {};
                            console.log(`control : ${device.DeviceID.toString()}/${control.ControlID.toString()}`);
                            gateway[member.Friend.toString()].Device[device.DeviceID.toString()].Control[control.ControlID.toString()] = {
                              ControlType: control.ConTypeID,
                              Label: control.Label,
                              Value: control.LastValue
                            };
                            /*devieItem[device.DeviceID.toString()].Control[control.ControlID.toString()].ControlType = control.ConTypeID;
                            devieItem[device.DeviceID.toString()].Control[control.ControlID.toString()].Label = control.Label;
                            devieItem[device.DeviceID.toString()].Control[control.ControlID.toString()].Value = control.LastValue;*/
                          });
                        }).catch((error) => {
                          console.error(`Error : ${error.message}`);
                        })


                    });


                  }).catch((error) => {
                    console.error(`Error : ${error.message}`);
                  })
              });

              console.log(`Gateway : ${JSON.stringify(gateway)}`);
              let p = {
                Success: true,
                Message: "",
                Member: gateway
              };

              const report = sendPackage(command.FriendInformation, JSON.stringify(p));
              sock.write(report);

            }).catch((error) => {
              console.error(`Error : ${error.message}`);
            })
        }
      }
    }


    /*
 
    (async () => {
      //Get Device
      await querys('SELECT * FROM Friends WHERE MemberID = :mid', { mid: Object.keys(dev) }).then((mem) => {
        //console.log('Query result:', res3.response);
        
        (async () => {
          //Get Control
          await querys('SELECT * FROM Friends WHERE MemberID = :mid', { mid: Object.keys(dev) }).then((mem) => {
            //console.log('Query result:', res3.response);
            
            
          }).catch((error) => {
            console.error(`Error : ${error.message}`);
          })
        })
      }).catch((error) => {
        console.error(`Error : ${error.message}`);
      })
    })*/


    /*Uint16Array(53) [
      1,  51,   1,   0, 123,  34,  85, 115, 101, 114, 110,
     97, 109, 101,  34,  58,  34, 104,  97, 109,  34,  44,
     34,  80,  97, 115, 115, 119, 111, 114, 100,  34,  58,
     34,  49,  50,  51,  52,  53,  54,  34,  44,  34,  84,
    111, 107, 101, 110,  34,  58,  34,  34, 125
  ]*/













    // Write the data back to all the connected, the client will receive it as data from the server
    /*let params = JSON.parse(data);
    sockets.forEach(function (sock, index, array) {
      sock.write(
        sock.remoteAddress +
          ":" +
          sock.remotePort +
          " said " +
          params.params.username +
          "\n"
      );
    });
    wsClient.forEach(function (wsc, index, array) {
      wsc.send(
        sock.remoteAddress +
          ":" +
          sock.remotePort +
          " said " +
          params.params.username +
          "\n"
      );
    });*/
  });

  // Add a 'close' event handler to this instance of socket
  sock.on("close", function (data) {
    let index = sockets.findIndex(function (o) {
      return (
        o.remoteAddress === sock.remoteAddress &&
        o.remotePort === sock.remotePort
      );
    });
    if (index !== -1) sockets.splice(index, 1);
    console.log("CLOSED: " + sock.remoteAddress + " " + sock.remotePort);
  });
});


function verifyPackage(_package) {
  /*let pg = '';
  _package.forEach(_pg => {
    pg += `${_pg.toString(16).toUpperCase()} `;
  });
  console.log(pg);*/
  //max 32965
  let countQnt = 0; //Quantity of length byte
  let len = 0; //payload length included command 2 byte
  let cmdL = 0;
  let cmdH = 0;
  if (_package.length > 0) {
    countQnt = _package[0];
  }
  //console.log(_package[0], _package[1], _package[2], _package[3], _package[4]);
  if (countQnt > 0) {
    len += _package[1];
    if (countQnt > 1) {
      len += _package[2] * (0xff + 1);
    }
    if (countQnt > 2) {
      len += _package[3] * (0xffff + 1);
    }
    if (countQnt > 3) {
      len += _package[4] * (0xffffff + 1);
    }
    if (countQnt > 4) {
      len += _package[5] * (0xffffffff + 1);
    }

    cmdL = _package[countQnt + 1];
    cmdH = _package[countQnt + 2];

    let buff = _package.slice(countQnt + 3);
    //console.log(`b:${buff.length} = len:${(len - 2)}`);
    if (buff.length == (len - 2)) {
      //console.log("slice: " + buff);
      let payload = bufferToString(buff);
      //console.log("payload: " + payload);
      return { cmd: (cmdH * 256 + cmdL), payload: payload, length: len };
    }
    else {
      return { cmd: -1, payload: 'Payload invalid.', length: 0 };
    }

  }
}

function sendPackage(_cmd, _payload) {

  let len = _payload.length + 2;
  let qlen = 0;
  let indx = 0;

  let buff = [];
  //Header
  let lenb = intToByteArray(len);

  buff.push(lenb.length);
  for (let i = 0; i < lenb.length; i++) {
    buff.push(lenb[i]);
  }
  //Command
  let c = intToByteArray(_cmd);
  buff.push(c[0]);
  buff.push(c[1] ? c[1] : 0);

  //Payload
  const buffer = Buffer.from(_payload, 'utf-8');
  console.log(`send package:${_cmd},${buffer}`);

  buffer.forEach(bf => {
    buff.push(bf);
  });

  /*let bb = '';
  buff.forEach(b => {
    bb += `{${b.toString(16).toUpperCase()}}`;
  });
  console.log(bb);*/
  return Buffer.from(buff);
}

function intToByteArray(int) {
  let byteArray = [];
  while (int > 0) {
    byteArray.push(int & 0xFF); // Get the last 8 bits of the integer
    int = int >> 8; // Shift right by 8 bits
  }
  return byteArray.reverse(); // Reverse the array to get the correct order
}

function bufferToString(_buffer) {
  const decoder = new TextDecoder();
  let str = decoder.decode(_buffer);
  str = str.replace(/\0/g, ''); // Remove null bytes
  return str;
}

module.exports = app;
