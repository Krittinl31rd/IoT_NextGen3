require("dotenv").config();
var createError = require("http-errors");
var express = require("express");
var path = require("path");
var cookieParser = require("cookie-parser");
var logger = require("morgan");
const bcrypt = require("bcrypt");
var indexRouter = require("./routes/index");
var usersRouter = require("./routes/users");
const { v4: uuidv4 } = require("uuid");
const {
  command,
  loginStatus,
  onDeviceControlType,
  friendRight,
  deviceType,
  deviceControlType,
  connectionStatusType,
  disconnectTypeEnum,
} = require("./models/common");

//const sql = require('mssql')
const { Member } = require("./db/models");
let { query, querys, excute, excutes } = require("./db/sql");

const fs = require("fs");
const http = require("http");
const WebSocket = require("ws");

const WebSocketAdminManager = require("./server/websocketadminserver");

var app = express();

const route = "/iot";
// view engine setup
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(logger("dev"));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(route + "/", express.static(path.join(__dirname, "public")));

app.use(route + "/", indexRouter);

app.use(route + "/users", usersRouter);

app.get("/", function (req, res, next) {
  res.send("Hello IoT. Please go to /iot");
});
app.get(route + "/iot/", function (req, res, next) {
  res.send("Hello IoT");
});

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

  // WebSocketAdminManager.sendLog("error", {
  //   datestamp: Date.toLocaleDateString(),
  //   timestamp: Date.toLocaleTimeString([], {
  //     hour: "2-digit",
  //     minute: "2-digit",
  //     second: "2-digit",
  //     hour12: false, // 24-hour format
  //   }),
  //   cmd: admincommand.Error,
  //   message: `[HTTP]${err.status || 500}`,
  // });
});

////////////////////////////////////////////////////////////////////////////////////////
//[ Setup Admin WebSocket ]//////////////////////////////////////////////////////////////////////////////////////////////////////////
let wsadminserver; // = http.createServer(app);
if (process.env.SECURE == "true") {
  wsadminserver = https.createServer(app, serverOptions);
} else {
  wsadminserver = http.createServer(app);
}
WebSocketAdminManager.on("messageReceived", (message) => {
  console.log(`[ADMIN] Message received in app.js: ${message}`);
});
WebSocketAdminManager.initialize(wsadminserver);

// wsadminserver.listen(
//   process.env.WS_ADMIN_PORT || 1010,
//   process.env.WS_ADMIN_HOST,
//   () => {
//     let sc = process.env.SECURE == "true" ? "wss" : "ws";
//     let host =
//       process.env.WS_ADMIN_HOST == "127.0.0.1"
//         ? "localhost"
//         : process.env.WS_ADMIN_HOST;

//     console.log(
//       `[ADMIN]\tServer running at ${sc}://${host}:${process.env.WS_ADMIN_PORT}${process.env.WS_ADMIN_PATH}`
//     );
//   }
// );
//////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Websocket
 */

// Create an HTTPS server
const serverOptions = {
  cert: fs.readFileSync("cert/cert.pem", "utf8"),
  key: fs.readFileSync("cert/key.pem", "utf8"),
};
var server = http.createServer(app);

// Create a WebSocket server bound to the HTTPS server
const wss = new WebSocket.Server({
  server: server,
  path: process.env.WS_PATH || "/echo",
});

let pingIntervalTime = 5000; // Ping interval (ms)
let pongIntervalTime = pingIntervalTime * 3 + 1000; // Pong Timeout (ms)[(pingIntervalTime X 3) + 1 Sec]
let anonymousTime = pingIntervalTime + 1000; // Inactive Timeout (ms)[pongIntervalTime + 1 Sec]
let minimumPacket = 4; //Minimum byte count for decode packet

var wsClient = [];
WebSocketAdminManager.socketClient.ws = wsClient;
wss.on("connection", function connection(ws, req) {
  const clientIP = req.socket.remoteAddress;
  const clientPort = req.socket.remotePort;

  console.log(`> [Client] [${clientIP}:${clientPort}] Connected`);

  let csock = {
    id: uuidv4(),
    //buffer: new Uint16Array(),
    lastTimestamp: new Date().getTime(),
    timestamp: new Date(),
    socket: ws,
    info: {
      id: 0,
      name: "",
      role: deviceType.Undefind,
      friend: [], //{MemberID, Role}
    },
    islogin: false,
  };

  wsClient.push(csock);

  let pongTimeout = null;
  WebSocketAdminManager.clientConnect("ws", csock);

  WebSocketAdminManager.sendLog("connect", {
    datestamp: csock.timestamp.toLocaleDateString(),
    timestamp: csock.timestamp.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false, // 24-hour format
    }),
    cmd: admincommand.Connect,
    message: `[WS]${clientIP}:${clientPort}`,
  });

  //if client inactive
  let anonymousTimeout = setTimeout(function () {
    console.log(`> [Client] [${clientIP}:${clientPort}] timeout`);
    let pr = {
      Message: "Inactive disconnect!",
    };
    //const report = sendPacket(command.ServerMessage, JSON.stringify(pr));
    ws.send(JSON.stringify(pr));
    //Kick client
    ws.close();
  }, anonymousTime);

  //Ping packet to client
  /*let pingInterval = setInterval(function () {
    if (csock.islogin == true) {
      let p = { cmd: command.Ping, param: { p: 'pi' } };
      //const report = sendPacket(command.Ping, JSON.stringify(p));
      //console.log(JSON.stringify(p));
      ws.send(JSON.stringify(p));
      console.log(`> [Ping] Send ping to [${csock.id}]`);
      //console.log(pongTimeout);
      //if timeout handle client(Disconnect)
      if (pongTimeout == null) {
        pongTimeout = setTimeout(function () {
          console.log(`> [Pong] [${csock.id}] Pong timeout`);
          let pr = {
            Message: 'Pong timeout. Will close your connection.'
          };
          //const pongreport = sendPacket(command.ServerMessage, JSON.stringify(pr));
          ws.send(JSON.stringify(pr));
          //Disconnect client
          ws.close();
        }, pongIntervalTime);
      }
    }
  }, pingIntervalTime);*/

  ws.on("message", function incoming(message) {
    //console.log("received: %s", message);

    let response = null;

    try {
      response = JSON.parse(message);
    } catch (err) {
      console.log(`> [WS Recieve.Error] : ${err}`);
    }

    if (response != undefined) {
      let jpayload = response.param;
      if (response.cmd == command.Login) {
        if (jpayload.Username && jpayload.Username != "") {
          (async () => {
            try {
              // Perform the query
              // console.log(jpayload);
              const member = await Member.findOne({
                where: {
                  Username: jpayload.Username, // Condition to match the Username field
                },
              });
              // Handle the case where no member is found
              console.log(":::::::::::::::::::::::::::::" + member);
              if (member) {
                bcrypt.compare(
                  jpayload.Password,
                  member.Password,
                  function (err, result) {
                    if (err) {
                      console.log(`Crypto.Error : ${err}`);
                    } else {
                      console.log(
                        `> [Auth] [${member.MemberName}] Authentication : ${result}`
                      );
                      if (result == true) {
                        //console.log(`Login : ${sock.remoteAddress}:${sock.remotePort}`);
                        //Stop kick inactive client
                        clearTimeout(anonymousTimeout);
                        anonymousTimeout = null;

                        console.log(
                          `> [Client] [${req.socket.remoteAddress}:${req.socket.remotePort} is ${member.MemberName}]`
                        );

                        let p = {
                          cmd: command.Login,
                          param: {
                            Success: true,
                            MemberID: member.MemberID,
                            Name: `${member.MemberName}`,
                            DeviceType: member.DeviceType,
                            Status: loginStatus.Success,
                            Message: "Welcome to IOT Server",
                          },
                        };
                        csock.info.role =
                          member.DeviceType == 1
                            ? deviceType.User
                            : member.DeviceType == 2
                            ? deviceType.Device
                            : deviceType.DeviceByteArray;
                        csock.islogin = true;
                        //console.log(`sock : ${JSON.stringify(csock.info)}`);
                        csock.info.id = member.MemberID;
                        csock.info.name = member.MemberName;
                        csock.timestamp = new Date();
                        //console.log(`sock : ${JSON.stringify(csock.info)}`);

                        //let soc = sockets.find(item => item.socket === sock);
                        //console.log(`sock : ${JSON.stringify(soc.info)}`);

                        //const report = sendPacket(command.Login, JSON.stringify(p));
                        ws.send(JSON.stringify(p));

                        WebSocketAdminManager.clientUpdateInfo("ws", csock);

                        WebSocketAdminManager.sendLog("login", {
                          datestamp: csock.timestamp.toLocaleDateString(),
                          timestamp: csock.timestamp.toLocaleTimeString([], {
                            hour: "2-digit",
                            minute: "2-digit",
                            second: "2-digit",
                            hour12: false, // 24-hour format
                          }),
                          cmd: command.Login,
                          message: `[WS]${clientIP}:${clientPort} as [${member.MemberID}] ${member.MemberName}`,
                        });
                        //if member is Device, Then get friend list
                        if (csock.info.role != deviceType.User) {
                          //Get friend
                          (async () => {
                            let friendResult = await querys(
                              "SELECT * FROM Friends WHERE Friend = :fid",
                              { fid: csock.info.MemberID }
                            );
                            //console.log(memberResult);
                            if (friendResult.response.length > 0) {
                              let friendPromises = friendResult.response.map(
                                async (friend) => {
                                  //console.log(friend);
                                  if (friend != undefined) {
                                    let fr = {
                                      memberID: friend.MemberID,
                                      role: friend.FRID,
                                    };
                                    csock.info.friend.push(fr);
                                    //console.log(fr);
                                    //---------------------------------------------------------------------------------
                                    console.log(
                                      `> [Device Status] [${gwmem.MemberName}] Online`
                                    );
                                    //Broadcast to friend user
                                    let p = {
                                      MemberID: gwmem.MemberID,
                                      Status: 1,
                                    };
                                    sendToMyFriend(
                                      command.FriendStatus,
                                      p,
                                      friend.MemberID
                                    );
                                    //----------------------------------------------------------------------------------
                                  }
                                }
                              );
                              await Promise.all(friendPromises); // Wait for all friend queries
                            }
                          })();
                        }
                      } else {
                        //{"Success":false,"MemberID":0,"Name":"","DeviceType":0,"Status":1,"Message":"password is invalid"}
                        let p = {
                          cmd: command.Login,
                          param: {
                            Success: false,
                            MemberID: 0,
                            Name: "",
                            DeviceType: 0,
                            Status: loginStatus.WrongUsernameOrPassword,
                            Message: "password is invalid",
                          },
                        };
                        //const report = sendPacket(command.Login, JSON.stringify(p));
                        ws.send(JSON.stringify(p));
                      }
                    }
                  }
                );
                //console.log(`Member found: ${JSON.stringify(member)}`);
              } else {
                //{"Success":false,"MemberID":0,"Name":"","DeviceType":0,"Status":1,"Message":"password is invalid"}
                let p = {
                  cmd: command.Login,
                  param: {
                    Success: false,
                    MemberID: 0,
                    Name: "",
                    DeviceType: 0,
                    Status: loginStatus.WrongUsernameOrPassword,
                    Message: "Username not found.",
                  },
                };
                //const report = sendPacket(command.Login, JSON.stringify(p));
                sock.write(JSON.stringify(p));
                //console.log(`No member found with username: ${jpayload.Username}`);
              }
            } catch (error) {
              console.error(`> [Error] fetching member: ${error.message}`);
            }
          })(); // Invoke the async function
        } else if (jpayload.Token && jpayload.Token != "") {
          //console.log(`Token : ${jpayload.Token}`);
          // Get devices
          (async () => {
            let tokenResult = await querys(
              "SELECT TOP(1) * FROM MemberTokenLogin WHERE Token = :token",
              { token: jpayload.Token }
            );
            console.log(`tokenResult : ${tokenResult.response.length}`);
            if (tokenResult.response.length > 0) {
              let tokenPromises = tokenResult.response.map(async (token) => {
                if (token != undefined) {
                  let memId = token.MemberID;
                  let expire = token.Expire;
                  let memberResult = await querys(
                    "SELECT TOP(1) * FROM Member WHERE MemberID = :mid",
                    { mid: memId }
                  );
                  //console.log(memberResult);
                  if (memberResult.response.length > 0) {
                    let memberPromises = memberResult.response.map(
                      async (gwmem) => {
                        //console.log(gwmem);
                        if (gwmem != undefined) {
                          //Stop kick inactive client
                          clearTimeout(anonymousTimeout);
                          anonymousTimeout = null;

                          //Check client dupplicate
                          let cdup = sockets.find(
                            (x) => x.info.id == gwmem.MemberID
                          );
                          let wscdup = wsClient.find(
                            (x) => x.info.id == gwmem.MemberID
                          );
                          if (cdup == undefined && wscdup == undefined) {
                            console.log(
                              `> [Client] [${clientIP}:${clientPort} is ${gwmem.MemberName}]`
                            );
                            let p = {
                              cmd: command.Login,
                              param: {
                                Success: true,
                                MemberID: gwmem.MemberID,
                                Name: `${gwmem.MemberName}`,
                                DeviceType: gwmem.DeviceType,
                                Status: loginStatus.Success,
                                Message: "Welcome to IOT Server",
                              },
                            };
                            csock.info.role =
                              gwmem.DeviceType == 1
                                ? deviceType.User
                                : gwmem.DeviceType == 2
                                ? deviceType.Device
                                : deviceType.DeviceByteArray;
                            csock.islogin = true;
                            //console.log(`sock : ${JSON.stringify(csock.info)}`);
                            csock.info.id = gwmem.MemberID;
                            csock.info.name = gwmem.MemberName;

                            csock.timestamp = new Date();
                            //console.log(`sock : ${JSON.stringify(csock.info)}`);

                            //let soc = sockets.find(item => item.socket === sock);
                            //console.log(`sock : ${JSON.stringify(soc.info)}`);

                            //const report = sendPacket(command.Login, JSON.stringify(p));
                            ws.send(JSON.stringify(p));

                            WebSocketAdminManager.clientUpdateInfo("ws", csock);

                            WebSocketAdminManager.sendLog("login", {
                              datestamp: csock.timestamp.toLocaleDateString(),
                              timestamp: csock.timestamp.toLocaleTimeString(
                                [],
                                {
                                  hour: "2-digit",
                                  minute: "2-digit",
                                  second: "2-digit",
                                  hour12: false, // 24-hour format
                                }
                              ),
                              cmd: command.Login,
                              message: `[WS]${clientIP}:${clientPort} as [${member.MemberID}] ${member.MemberName}`,
                            });
                            //console.log(`> [Device Status] [${gwmem.MemberName}] Online`);
                            //if member is Device, Then get friend list
                            if (csock.info.role != deviceType.User) {
                              //Get friend
                              let friendResult = await querys(
                                "SELECT * FROM Friends WHERE Friend = :fid",
                                { fid: gwmem.MemberID }
                              );
                              //console.log(memberResult);
                              if (friendResult.response.length > 0) {
                                let friendPromises = friendResult.response.map(
                                  async (friend) => {
                                    //console.log(friend);
                                    if (friend != undefined) {
                                      let fr = {
                                        memberID: friend.MemberID,
                                        role: friend.FRID,
                                      };
                                      csock.info.friend.push(fr);
                                      //console.log(fr);
                                      //---------------------------------------------------------------------------------

                                      //Broadcast to friend user
                                      let p = {
                                        MemberID: gwmem.MemberID,
                                        Status: 1,
                                      };
                                      sendToMyFriend(
                                        command.FriendStatus,
                                        p,
                                        friend.MemberID
                                      );
                                      //----------------------------------------------------------------------------------
                                    }
                                  }
                                );
                                await Promise.all(friendPromises); // Wait for all friend queries
                              }
                            }
                          } else {
                            //Reject command
                            let p = {
                              Status: 0,
                              Message: "Command reject, (Dupplicate login)",
                            };
                            //const report = sendPacket(command.CommandReject, JSON.stringify(p));
                            ws.send(JSON.stringify(p));
                            ws.close();
                          }
                        }
                      }
                    );
                    await Promise.all(memberPromises); // Wait for all device queries
                  }
                }
              });
              await Promise.all(tokenPromises); // Wait for all device queries
            } else {
              //Reject command
              let p = {
                Status: 0,
                Message: "Command reject, (User not found)",
              };
              //const report = sendPacket(command.CommandReject, JSON.stringify(p));
              ws.send(JSON.stringify(p));
              ws.close();
              console.log("> [Auth] Not found");
            }
          })();
        } else {
          console.log("> [Auth] Username is undefined or null");
        }
      } else if (response.cmd == command.Logout) {
        //Logout
        if (csock.islogin == false) {
          //Reject command
          let p = {
            Status: 0,
            Message: "Command reject",
          };
          //const report = sendPacket(command.CommandReject, JSON.stringify(p));
          ws.send(JSON.stringify(p));
          csock.timestamp = new Date();
          WebSocketAdminManager.sendLog("reject", {
            datestamp: csock.timestamp.toLocaleDateString(),
            timestamp: csock.timestamp.toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
              second: "2-digit",
              hour12: false, // 24-hour format
            }),
            cmd: admincommand.Logout,
            message: `[WS]Reject ${clientIP}:${clientPort} because not login.`,
          });
        } else {
          csock.islogin = false;
          csock.info = {};
          clearInterval(pingInterval);
          console.log(
            `> [Client] [${csock.info.name} - ${sock.remoteAddress}:${sock.remotePort}] Logout`
          );
          csock.timestamp = new Date();
          WebSocketAdminManager.sendLog("logout", {
            datestamp: csock.timestamp.toLocaleDateString(),
            timestamp: csock.timestamp.toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
              second: "2-digit",
              hour12: false, // 24-hour format
            }),
            cmd: admincommand.Logout,
            message: `[WS][${csock.info.id}]${csock.info.name} | (${clientIP}:${clientPort}) Loged-out`,
          });
        }
      } else if (response.cmd == command.Ping) {
        console.log(`> [Ping] [${csock.info.name}] want to know server status`);
        let p = {
          cmd: command.Pong,
          param: {
            p: "pi",
          },
        };
        //const report = sendPacket(command.CommandReject, JSON.stringify(p));
        ws.send(JSON.stringify(p));
      } else if (response.cmd == command.Pong) {
        console.log(`> [Pong] [${csock.info.name}] pong response`);

        clearTimeout(pongTimeout);
        pongTimeout = null;
      } else if (response.cmd == command.Configuration) {
        //Config, From user to gateway
        if (csock.islogin == false) {
          //Reject command
          let p = {
            cmd: command.CommandReject,
            param: {
              Status: 0,
              Message: "Command reject",
            },
          };
          //const report = sendPacket(command.CommandReject, JSON.stringify(p));
          csock.timestamp = new Date();
          WebSocketAdminManager.sendLog("reject", {
            datestamp: csock.timestamp.toLocaleDateString(),
            timestamp: csock.timestamp.toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
              second: "2-digit",
              hour12: false, // 24-hour format
            }),
            cmd: command.Configuration,
            message: `[WS]Reject ${clientIP}:${clientPort} - [${jpayload.Member}] because not login.`,
          });
          ws.send(JSON.stringify(p));
        } else {
          if (csock.info.role != deviceType.User) {
            let p = {
              cmd: command.CommandReject,
              param: {
                Status: 0,
                Message: "Command reject, Device cannot control device.",
              },
            };
            //const report = sendPacket(command.CommandReject, JSON.stringify(p));
            csock.timestamp = new Date();
            WebSocketAdminManager.sendLog("reject", {
              datestamp: csock.timestamp.toLocaleDateString(),
              timestamp: csock.timestamp.toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
                hour12: false, // 24-hour format
              }),
              cmd: command.Configuration,
              message: `[WS]Reject[${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [${jpayload.Member}] because Device cannot config device.`,
            });
            ws.send(JSON.stringify(p));
          } else {
            console.log(
              `> [config] From [${csock.info.id}] : ${JSON.stringify(jpayload)}`
            );

            //let payloadString = payload.toString('utf-8');

            let gw = sockets.find((x) => x.info.id == jpayload.Member);
            let wsgw = wsClient.find((x) => x.info.id == jpayload.Member);
            // console.log(`config : ${gw}/${wsgw}`);
            if (gw != undefined) {
              //console.log(`Gateway : [${gw.info.name}]`);
              //Get friend right
              let myFriend = gw.info.friend.find(
                (x) => x.memberID == csock.info.id
              );
              if (myFriend != undefined) {
                //console.log(`myFriend : ${myFriend.memberID}`);
                if (
                  myFriend.role != friendRight.DeviceMonitor &&
                  myFriend.role != friendRight.NotFriend
                ) {
                  //Grant Control

                  let p = {
                    Member: jpayload.Member,
                    config: jpayload,
                  };
                  const report = sendPacket(
                    command.Configuration,
                    JSON.stringify(p)
                  );
                  gw.socket.write(report);
                  csock.timestamp = new Date();
                  WebSocketAdminManager.sendLog("config", {
                    datestamp: csock.timestamp.toLocaleDateString(),
                    timestamp: csock.timestamp.toLocaleTimeString([], {
                      hour: "2-digit",
                      minute: "2-digit",
                      second: "2-digit",
                      hour12: false, // 24-hour format
                    }),
                    cmd: command.Configuration,
                    message: `[WS][${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [Member: ${jpayload.Member}]`,
                  });
                } else {
                  //cannot control, No permission
                  let p = {
                    cmd: command.CommandReject,
                    param: {
                      Status: 0,
                      Message: "Command reject, Cannot config. Monitor only.",
                    },
                  };
                  console.log(p);
                  //const report = sendPacket(command.CommandReject, JSON.stringify(p));
                  csock.timestamp = new Date();
                  WebSocketAdminManager.sendLog("reject", {
                    datestamp: csock.timestamp.toLocaleDateString(),
                    timestamp: csock.timestamp.toLocaleTimeString([], {
                      hour: "2-digit",
                      minute: "2-digit",
                      second: "2-digit",
                      hour12: false, // 24-hour format
                    }),
                    cmd: command.Configuration,
                    message: `[WS]Reject[${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [${jpayload.Member}] because Cannot config. Monitor only.`,
                  });
                  ws.send(JSON.stringify(p));
                }
              } else {
                let p = {
                  cmd: command.CommandReject,
                  param: {
                    Status: 0,
                    Message: "Command reject, No permission.",
                  },
                };
                console.log(p);
                //const report = sendPacket(command.CommandReject, JSON.stringify(p));
                csock.timestamp = new Date();
                WebSocketAdminManager.sendLog("reject", {
                  datestamp: csock.timestamp.toLocaleDateString(),
                  timestamp: csock.timestamp.toLocaleTimeString([], {
                    hour: "2-digit",
                    minute: "2-digit",
                    second: "2-digit",
                    hour12: false, // 24-hour format
                  }),
                  cmd: command.Configuration,
                  message: `[WS]Reject[${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [${jpayload.Member}] because No permission.`,
                });
                ws.send(JSON.stringify(p));
              }
            } else if (wsgw != undefined) {
              //console.log(`Gateway : [${gw.info.name}]`);
              //Get friend right
              let myFriend = wsgw.info.friend.find(
                (x) => x.memberID == csock.info.id
              );
              if (myFriend != undefined) {
                //console.log(`myFriend : ${myFriend.memberID}`);
                if (
                  myFriend.role != friendRight.DeviceMonitor &&
                  myFriend.role != friendRight.NotFriend
                ) {
                  //Grant Control

                  let p = {
                    cmd: command.Configuration,
                    param: {
                      Member: jpayload.Member,
                      config: jpayload,
                    },
                  };
                  //const report = sendPacket(command.DeviceControl, JSON.stringify(p));
                  csock.timestamp = new Date();
                  WebSocketAdminManager.sendLog("config", {
                    datestamp: csock.timestamp.toLocaleDateString(),
                    timestamp: csock.timestamp.toLocaleTimeString([], {
                      hour: "2-digit",
                      minute: "2-digit",
                      second: "2-digit",
                      hour12: false, // 24-hour format
                    }),
                    cmd: command.Configuration,
                    message: `[WS][${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [Member: ${jpayload.Member}]`,
                  });
                  wsgw.socket.send(JSON.stringify(p));
                  /*
                  let p = {
                    Member: jpayload.Member,
                    Device: jpayload.Device,
                    Ctrl: jpayload.Ctrl,
                    V: jpayload.V,
                    R: jpayload.R
                  };
                  const report = sendPacket(command.DeviceUpdateValue, JSON.stringify(p));
                  sock.write(report);*/
                } else {
                  //cannot control, No permission
                  let p = {
                    cmd: command.CommandReject,
                    param: {
                      Status: 0,
                      Message: "Command reject, Cannot control. Monitor only.",
                    },
                  };
                  console.log(p);
                  //const report = sendPacket(command.CommandReject, JSON.stringify(p));
                  csock.timestamp = new Date();
                  WebSocketAdminManager.sendLog("reject", {
                    datestamp: csock.timestamp.toLocaleDateString(),
                    timestamp: csock.timestamp.toLocaleTimeString([], {
                      hour: "2-digit",
                      minute: "2-digit",
                      second: "2-digit",
                      hour12: false, // 24-hour format
                    }),
                    cmd: command.Configuration,
                    message: `[WS]Reject[${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [${jpayload.Member}] because Cannot config. Monitor only.`,
                  });
                  ws.send(JSON.stringify(p));
                }
              } else {
                let p = {
                  cmd: command.CommandReject,
                  param: {
                    Status: 0,
                    Message: "Command reject, No permission.",
                  },
                };
                console.log(p);
                //const report = sendPacket(command.CommandReject, JSON.stringify(p));
                csock.timestamp = new Date();
                WebSocketAdminManager.sendLog("reject", {
                  datestamp: csock.timestamp.toLocaleDateString(),
                  timestamp: csock.timestamp.toLocaleTimeString([], {
                    hour: "2-digit",
                    minute: "2-digit",
                    second: "2-digit",
                    hour12: false, // 24-hour format
                  }),
                  cmd: command.Configuration,
                  message: `[WS]Reject[${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [${jpayload.Member}] because No permission.`,
                });
                ws.send(JSON.stringify(p));
              }
              //end ws phase
            } else {
              let p = {
                cmd: command.CommandReject,
                param: {
                  Status: 0,
                  Message:
                    "Command reject(not found target or Offline), Target not found or Offline.",
                },
              };
              console.log(p);
              //const report = sendPacket(command.CommandReject, JSON.stringify(p));
              csock.timestamp = new Date();
              WebSocketAdminManager.sendLog("config", {
                datestamp: csock.timestamp.toLocaleDateString(),
                timestamp: csock.timestamp.toLocaleTimeString([], {
                  hour: "2-digit",
                  minute: "2-digit",
                  second: "2-digit",
                  hour12: false, // 24-hour format
                }),
                cmd: command.Configuration,
                message: `[WS][${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [Member: ${jpayload.Member}] Target not found or Offline.`,
              });
              csock.socket.send(JSON.stringify(p));
            }
          }
        }
      } else if (response.cmd == command.Logs) {
        // Logs, From gateway to user
        if (csock.islogin == false) {
          //Reject command
          let p = {
            cmd: command.CommandReject,
            param: {
              Status: 0,
              Message: "Command reject",
            },
          };
          console.log(p);
          //const report = sendPacket(command.CommandReject, JSON.stringify(p));
          csock.timestamp = new Date();
          // WebSocketAdminManager.sendLog("reject", {
          //   datestamp: csock.timestamp.toLocaleDateString(),
          //   timestamp: csock.timestamp.toLocaleTimeString([], {
          //     hour: "2-digit",
          //     minute: "2-digit",
          //     second: "2-digit",
          //     hour12: false, // 24-hour format
          //   }),
          //   cmd: admincommand.Logs,
          //   message: `[TCP]Reject ${clientIP}:${clientPort} - [Device ${jpayload.device_id}] because not login.`,
          // });
          ws.send(JSON.stringify(p));
        } else {
          console.log(
            `> [Logs] From [${csock.info.id}] : ${JSON.stringify(jpayload)}`
          );
          //Broadcast to friend user
          //csock.info.friend

          //console.log(csock.info);
          (async () => {
            let isGateway = await excutes(
              `SELECT lc.site_id, lg.id AS gateway_id, lg.gateway_name 
                  FROM Lamp_Gateways lg
                  JOIN Lamp_Contracts lc ON lg.contract_id = lc.id
                  WHERE lg.id = :gateway_id`,
              {
                gateway_id: csock.info.id,
              }
            );
            if (isGateway.response[0].length > 0) {
              const detail = {
                gateway_id: csock.info.id,
                device_id: jpayload.device_id,
                input: {
                  volt: jpayload.c13,
                  current: jpayload.c14,
                },
                output: {
                  volt: jpayload.c15,
                  current: jpayload.c16,
                },
                battery: {
                  batt_volt: jpayload.c17,
                  capacity: jpayload.c18,
                  health: jpayload.c19,
                  cycle: jpayload.c20,
                  level: jpayload.c10,
                  charge: jpayload.c12,
                },
                env: { temp: jpayload.c11, humid: 0 },
                timestamp: convert(jpayload.timestamp),
              };
              const payload_detail = {
                type: "log",
                detail: JSON.stringify([detail]),
                control_by: csock.info.id,
                site_id: isGateway.response[0][0].site_id,
              };
              const d = new Date();
              await excutes(
                `INSERT INTO Lamp_Log (type, detail, control_by, created_at, site_id)
                   VALUES (:type, :detail, :control_by, :created_at, :site_id)`,
                {
                  type: payload_detail.type,
                  detail: payload_detail.detail,
                  control_by: payload_detail.control_by,
                  created_at: d.toISOString().slice(0, 23).replace("T", " "),
                  site_id: payload_detail.site_id,
                }
              );
              // const myFriend = getFriendOnline(csock);
              let p = {
                log_type: "log",
                gateway_id: csock.info.id,
                device_id: device_id,
                input: {
                  volt: jpayload.c13,
                  current: jpayload.c14,
                },
                output: {
                  volt: jpayload.c15,
                  current: jpayload.c16,
                },
                battery: {
                  batt_volt: jpayload.c17,
                  capacity: jpayload.c18,
                  health: jpayload.c19,
                  cycle: jpayload.c20,
                  level: jpayload.c10,
                  charge: jpayload.c12,
                },
                env: { temp: jpayload.c11, humid: 0 },
                created_at: d.toISOString().slice(0, 23).replace("T", " "),
              };

              let getf = getMyfriend(csock);

              if (getf != undefined) {
                getf.tcp.forEach((frd) => {
                  sendToMyFriendTCP(command.DeviceUpdateValue, p, frd);
                });
                getf.ws.forEach((frd) => {
                  sendToMyFriendWS(command.DeviceUpdateValue, p, frd);
                });
              }

              csock.timestamp = new Date();
              WebSocketAdminManager.sendLog("control", {
                datestamp: csock.timestamp.toLocaleDateString(),
                timestamp: csock.timestamp.toLocaleTimeString([], {
                  hour: "2-digit",
                  minute: "2-digit",
                  second: "2-digit",
                  hour12: false, // 24-hour format
                }),
                cmd: admincommand.DeviceUpdateValue,
                message: `[WS][${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [Member: ${csock.info.id}, Device: ${jpayload.Device}, Ctrl: ${jpayload.Ctrl}, V: ${jpayload.V}]`,
              });
            }
          })();
        }
      } else if (response.cmd == command.DeviceControl) {
        //Control, From user to gateway
        if (csock.islogin == false) {
          //Reject command
          let p = {
            cmd: command.CommandReject,
            param: {
              Status: 0,
              Message: "Command reject",
            },
          };
          //const report = sendPacket(command.CommandReject, JSON.stringify(p));
          csock.timestamp = new Date();
          WebSocketAdminManager.sendLog("reject", {
            datestamp: csock.timestamp.toLocaleDateString(),
            timestamp: csock.timestamp.toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
              second: "2-digit",
              hour12: false, // 24-hour format
            }),
            cmd: admincommand.DeviceControl,
            message: `[WS]Reject ${clientIP}:${clientPort} - [${jpayload.Member}:${jpayload.Device}:${jpayload.Ctrl}:${jpayload.V}] because not login.`,
          });
          ws.send(JSON.stringify(p));
        } else {
          if (csock.info.role != deviceType.User) {
            let p = {
              cmd: command.CommandReject,
              param: {
                Status: 0,
                Message: "Command reject, Device cannot control device.",
              },
            };
            //const report = sendPacket(command.CommandReject, JSON.stringify(p));
            csock.timestamp = new Date();
            WebSocketAdminManager.sendLog("reject", {
              datestamp: csock.timestamp.toLocaleDateString(),
              timestamp: csock.timestamp.toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
                hour12: false, // 24-hour format
              }),
              cmd: admincommand.DeviceControl,
              message: `[WS]Reject[${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [${jpayload.Member}:${jpayload.Device}:${jpayload.Ctrl}:${jpayload.V}] because Device cannot control device.`,
            });
            ws.send(JSON.stringify(p));
          } else {
            console.log(
              `> [Control] From [${csock.info.id}] : ${JSON.stringify(
                jpayload
              )}`
            );

            //let payloadString = payload.toString('utf-8');

            let gw = sockets.find((x) => x.info.id == jpayload.Member);
            let wsgw = wsClient.find((x) => x.info.id == jpayload.Member);
            console.log(`control : ${gw}/${wsgw}`);
            if (gw != undefined) {
              //console.log(`Gateway : [${gw.info.name}]`);
              //Get friend right
              let myFriend = gw.info.friend.find(
                (x) => x.memberID == csock.info.id
              );
              if (myFriend != undefined) {
                //console.log(`myFriend : ${myFriend.memberID}`);
                if (
                  myFriend.role != friendRight.DeviceMonitor &&
                  myFriend.role != friendRight.NotFriend
                ) {
                  //Grant Control

                  let p = {
                    Member: jpayload.Member,
                    Device: jpayload.Device,
                    Ctrl: jpayload.Ctrl,
                    V: jpayload.V,
                    R: jpayload.R,
                  };
                  const report = sendPacket(
                    command.DeviceControl,
                    JSON.stringify(p)
                  );
                  gw.socket.write(report);
                  csock.timestamp = new Date();
                  WebSocketAdminManager.sendLog("control", {
                    datestamp: csock.timestamp.toLocaleDateString(),
                    timestamp: csock.timestamp.toLocaleTimeString([], {
                      hour: "2-digit",
                      minute: "2-digit",
                      second: "2-digit",
                      hour12: false, // 24-hour format
                    }),
                    cmd: admincommand.DeviceControl,
                    message: `[WS][${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [Member: ${jpayload.Member}, Device: ${jpayload.Device}, Ctrl: ${jpayload.Ctrl}, V: ${jpayload.V}]`,
                  });
                } else {
                  //cannot control, No permission
                  let p = {
                    cmd: command.CommandReject,
                    param: {
                      Status: 0,
                      Message: "Command reject, Cannot control. Monitor only.",
                    },
                  };
                  console.log(p);
                  //const report = sendPacket(command.CommandReject, JSON.stringify(p));
                  csock.timestamp = new Date();
                  WebSocketAdminManager.sendLog("reject", {
                    datestamp: csock.timestamp.toLocaleDateString(),
                    timestamp: csock.timestamp.toLocaleTimeString([], {
                      hour: "2-digit",
                      minute: "2-digit",
                      second: "2-digit",
                      hour12: false, // 24-hour format
                    }),
                    cmd: admincommand.DeviceControl,
                    message: `[WS]Reject[${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [${jpayload.Member}:${jpayload.Device}:${jpayload.Ctrl}:${jpayload.V}] because Cannot control. Monitor only.`,
                  });
                  ws.send(JSON.stringify(p));
                }
              } else {
                let p = {
                  cmd: command.CommandReject,
                  param: {
                    Status: 0,
                    Message: "Command reject, No permission.",
                  },
                };
                console.log(p);
                //const report = sendPacket(command.CommandReject, JSON.stringify(p));
                csock.timestamp = new Date();
                WebSocketAdminManager.sendLog("reject", {
                  datestamp: csock.timestamp.toLocaleDateString(),
                  timestamp: csock.timestamp.toLocaleTimeString([], {
                    hour: "2-digit",
                    minute: "2-digit",
                    second: "2-digit",
                    hour12: false, // 24-hour format
                  }),
                  cmd: admincommand.DeviceControl,
                  message: `[WS]Reject[${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [${jpayload.Member}:${jpayload.Device}:${jpayload.Ctrl}:${jpayload.V}] because No permission.`,
                });
                ws.send(JSON.stringify(p));
              }
            } else if (wsgw != undefined) {
              //console.log(`Gateway : [${gw.info.name}]`);
              //Get friend right
              let myFriend = wsgw.info.friend.find(
                (x) => x.memberID == csock.info.id
              );
              if (myFriend != undefined) {
                //console.log(`myFriend : ${myFriend.memberID}`);
                if (
                  myFriend.role != friendRight.DeviceMonitor &&
                  myFriend.role != friendRight.NotFriend
                ) {
                  //Grant Control

                  let p = {
                    cmd: command.DeviceControl,
                    param: {
                      Member: jpayload.Member,
                      Device: jpayload.Device,
                      Ctrl: jpayload.Ctrl,
                      V: jpayload.V,
                      R: jpayload.R,
                    },
                  };
                  //const report = sendPacket(command.DeviceControl, JSON.stringify(p));
                  csock.timestamp = new Date();
                  WebSocketAdminManager.sendLog("control", {
                    datestamp: csock.timestamp.toLocaleDateString(),
                    timestamp: csock.timestamp.toLocaleTimeString([], {
                      hour: "2-digit",
                      minute: "2-digit",
                      second: "2-digit",
                      hour12: false, // 24-hour format
                    }),
                    cmd: admincommand.DeviceControl,
                    message: `[WS][${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [Member: ${jpayload.Member}, Device: ${jpayload.Device}, Ctrl: ${jpayload.Ctrl}, V: ${jpayload.V}]`,
                  });
                  wsgw.socket.send(JSON.stringify(p));
                  /*
                  let p = {
                    Member: jpayload.Member,
                    Device: jpayload.Device,
                    Ctrl: jpayload.Ctrl,
                    V: jpayload.V,
                    R: jpayload.R
                  };
                  const report = sendPacket(command.DeviceUpdateValue, JSON.stringify(p));
                  sock.write(report);*/
                } else {
                  //cannot control, No permission
                  let p = {
                    cmd: command.CommandReject,
                    param: {
                      Status: 0,
                      Message: "Command reject, Cannot control. Monitor only.",
                    },
                  };
                  console.log(p);
                  //const report = sendPacket(command.CommandReject, JSON.stringify(p));
                  csock.timestamp = new Date();
                  WebSocketAdminManager.sendLog("reject", {
                    datestamp: csock.timestamp.toLocaleDateString(),
                    timestamp: csock.timestamp.toLocaleTimeString([], {
                      hour: "2-digit",
                      minute: "2-digit",
                      second: "2-digit",
                      hour12: false, // 24-hour format
                    }),
                    cmd: admincommand.DeviceControl,
                    message: `[WS]Reject[${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [${jpayload.Member}:${jpayload.Device}:${jpayload.Ctrl}:${jpayload.V}] because Cannot control. Monitor only.`,
                  });
                  ws.send(JSON.stringify(p));
                }
              } else {
                let p = {
                  cmd: command.CommandReject,
                  param: {
                    Status: 0,
                    Message: "Command reject, No permission.",
                  },
                };
                console.log(p);
                //const report = sendPacket(command.CommandReject, JSON.stringify(p));
                csock.timestamp = new Date();
                WebSocketAdminManager.sendLog("reject", {
                  datestamp: csock.timestamp.toLocaleDateString(),
                  timestamp: csock.timestamp.toLocaleTimeString([], {
                    hour: "2-digit",
                    minute: "2-digit",
                    second: "2-digit",
                    hour12: false, // 24-hour format
                  }),
                  cmd: admincommand.DeviceControl,
                  message: `[WS]Reject[${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [${jpayload.Member}:${jpayload.Device}:${jpayload.Ctrl}:${jpayload.V}] because No permission.`,
                });
                ws.send(JSON.stringify(p));
              }
              //end ws phase
            } else {
              let p = {
                cmd: command.CommandReject,
                param: {
                  Status: 0,
                  Message:
                    "Command reject(not found target or Offline), Target not found or Offline.",
                },
              };
              console.log(p);
              //const report = sendPacket(command.CommandReject, JSON.stringify(p));
              csock.timestamp = new Date();
              WebSocketAdminManager.sendLog("control", {
                datestamp: csock.timestamp.toLocaleDateString(),
                timestamp: csock.timestamp.toLocaleTimeString([], {
                  hour: "2-digit",
                  minute: "2-digit",
                  second: "2-digit",
                  hour12: false, // 24-hour format
                }),
                cmd: admincommand.DeviceControl,
                message: `[WS][${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [Member: ${jpayload.Member}, Device: ${jpayload.Device}, Ctrl: ${jpayload.Ctrl}, V: ${jpayload.V}] Target not found or Offline.`,
              });
              csock.socket.send(JSON.stringify(p));
            }
          }
        }
      } else if (response.cmd == command.DeviceUpdateValue) {
        // gateway update device control
        if (csock.islogin == false) {
          //Reject command
          let p = {
            cmd: command.CommandReject,
            param: {
              Status: 0,
              Message: "Command reject",
            },
          };
          console.log(p);
          //const report = sendPacket(command.CommandReject, JSON.stringify(p));
          csock.timestamp = new Date();
          WebSocketAdminManager.sendLog("reject", {
            datestamp: csock.timestamp.toLocaleDateString(),
            timestamp: csock.timestamp.toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
              second: "2-digit",
              hour12: false, // 24-hour format
            }),
            cmd: admincommand.DeviceUpdateValue,
            message: `[WS]Reject ${clientIP}:${clientPort} - [Device ${jpayload.Device}:${jpayload.Ctrl}:${jpayload.V}] because not login.`,
          });
          ws.send(JSON.stringify(p));
        } else {
          console.log(
            `> [DeviceUpdateValue] From [${csock.info.id}] : ${JSON.stringify(
              jpayload
            )}`
          );
          //Broadcast to friend user
          //csock.info.friend

          //console.log(csock.info);
          (async () => {
            let updateDeviceControlResult = await excutes(
              "UPDATE DevicetControl set LastValue = :value where MemberID = :mid and DeviceID = :did and ControlID = :ctrlid",
              {
                value: jpayload.V,
                mid: csock.info.id,
                did: jpayload.Device,
                ctrlid: jpayload.Ctrl,
              }
            );
            // if (
            //   jpayload.Device >= 2000 &&
            //   jpayload.Device <= 2999 &&
            //   (jpayload.Ctrl === 1 || jpayload.Ctrl === 2)
            // ) {
            //   const isGateway = await excutes(
            //     `SELECT lc.site_id, lg.id AS gateway_id, lg.gateway_name
            //       FROM Lamp_Gateways lg
            //       JOIN Lamp_Contracts lc ON lg.contract_id = lc.id
            //       WHERE lg.id = :gateway_id`,
            //     {
            //       gateway_id: csock.info.id,
            //     }
            //   );

            //   if (isGateway.response[0].length > 0) {
            //     const payload_usage = {
            //       type: "usage",
            //       detail: JSON.stringify([
            //         {
            //           gateway_id: csock.info.id,
            //           device_id: jpayload.Device,
            //           control_id: jpayload.Ctrl,
            //           V: jpayload.V,
            //         },
            //       ]),
            //       control_by: csock.info.id,
            //       site_id: isGateway.response[0][0].site_id,
            //     };
            //     // console.log(payload_usage);
            //     const d = new Date();
            //     const updatedLogs = await excutes(
            //       `INSERT INTO Lamp_Log (type, detail, control_by, created_at, site_id)
            //        VALUES (:type, :detail, :control_by, :created_at, :site_id)`,
            //       {
            //         type: payload_usage.type,
            //         detail: payload_usage.detail,
            //         control_by: payload_usage.control_by,
            //         created_at: d.toISOString().slice(0, 23).replace("T", " "),
            //         site_id: payload_usage.site_id,
            //       }
            //     );
            //     console.log(
            //       `> [DeviceUpdateValue] Insert Log ${[
            //         csock.info.id,
            //       ]} : ${JSON.stringify(jpayload)}`
            //     );
            //   }
            // }
          })();

          //const myFriend = getFriendOnline(csock);
          let p = {
            Member: csock.info.id,
            Device: jpayload.Device,
            Ctrl: jpayload.Ctrl,
            V: jpayload.V,
            R: jpayload.R,
          };
          let getf = getMyfriend(csock);

          if (getf != undefined) {
            getf.tcp.forEach((frd) => {
              sendToMyFriendTCP(command.DeviceUpdateValue, p, frd);
            });
            getf.ws.forEach((frd) => {
              sendToMyFriendWS(command.DeviceUpdateValue, p, frd);
            });
          }

          csock.timestamp = new Date();
          WebSocketAdminManager.sendLog("control", {
            datestamp: csock.timestamp.toLocaleDateString(),
            timestamp: csock.timestamp.toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
              second: "2-digit",
              hour12: false, // 24-hour format
            }),
            cmd: admincommand.DeviceUpdateValue,
            message: `[WS][${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [Member: ${csock.info.id}, Device: ${jpayload.Device}, Ctrl: ${jpayload.Ctrl}, V: ${jpayload.V}]`,
          });
        }
      } else if (response.cmd == command.GetFriendInformation) {
        // get information
        if (csock.islogin == false) {
          //Reject command
          let p = {
            cmd: command.CommandReject,
            param: {
              Status: 0,
              Message: "Command reject",
            },
          };
          csock.timestamp = new Date();
          WebSocketAdminManager.sendLog("reject", {
            datestamp: csock.timestamp.toLocaleDateString(),
            timestamp: csock.timestamp.toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
              second: "2-digit",
              hour12: false, // 24-hour format
            }),
            cmd: admincommand.GetFriendInformation,
            message: `[WS]Reject ${clientIP}:${clientPort} because not login.`,
          });
          csock.socket.send(JSON.stringify(p));
        } else {
          console.log(`> [GetFriendInformation] [${csock.info.id}] : Request`);
          let gateway = {};
          (async () => {
            // Get gateway
            let memberResult = await querys(
              "SELECT Friends.MemberID as MemberID, Friends.Friend as Friend, Friends.FRID as FRID, Member.DeviceType as DeviceType, Member.MemberName as MemberName, Member.Img as Img FROM Friends inner join Member on Friends.Friend = Member.MemberID WHERE Friends.MemberID = :mid",
              { mid: csock.info.id }
            );
            // console.log(memberResult?.response);
            if (memberResult.response.length > 0) {
              let memberPromises = memberResult.response.map(async (member) => {
                let gwsock = sockets.find((x) => x.info.id == member.Friend);
                let gwwssock = wsClient.find((x) => x.info.id == member.Friend);
                gateway[member.Friend.toString()] = {
                  Status:
                    (gwsock != undefined && gwsock.islogin == true) ||
                    (gwwssock != undefined && gwwssock.islogin == true)
                      ? 1
                      : 0,
                  Img: member.Img,
                  Name: member.MemberName,
                  DeviceType: member.DeviceType,
                  Device: {},
                };
                // Get devices
                let deviceResult = await querys(
                  "SELECT * FROM Devices WHERE MemberID = :mid",
                  { mid: member.Friend }
                );
                if (deviceResult.response.length > 0) {
                  let devicePromises = deviceResult.response.map(
                    async (device) => {
                      gateway[member.Friend.toString()].Device[
                        device.DeviceID.toString()
                      ] = {
                        DeviceName: device.DeviceName,
                        DeviceStyleID: device.DeviceStyleID,
                        Control: {},
                      };
                      // Get control
                      let controlResult = await querys(
                        "SELECT * FROM DevicetControl WHERE MemberID = :mid and DeviceID = :did",
                        { mid: member.Friend, did: device.DeviceID }
                      );
                      if (controlResult.response.length > 0) {
                        //controlResult.response.forEach(control
                        let controlPromises = controlResult.response.map(
                          async (control) => {
                            gateway[member.Friend.toString()].Device[
                              device.DeviceID.toString()
                            ].Control[control.ControlID.toString()] = {
                              ControlType: control.ConTypeID,
                              Label: control.Label,
                              Value: control.LastValue,
                            };
                          }
                        );
                        await Promise.all(controlPromises); // Wait for all devicecontrol queries
                      }
                    }
                  );
                  await Promise.all(devicePromises); // Wait for all device queries
                }
              });
              await Promise.all(memberPromises); // Wait for all member-related queries
              //console.log(`Gateway : ${JSON.stringify(gateway)}`);
              let p = {
                cmd: command.FriendInformation,
                param: {
                  Success: true,
                  Message: "",
                  Member: gateway,
                },
              };
              csock.socket.send(JSON.stringify(p));
              //const report = sendPacket(command.FriendInformation, JSON.stringify(p));
              /*let bb = '';
              for (let j = 0; j < 100; j++) {
                bb += `{${report[j].toString(16).toUpperCase()}}`;
              }
              report.forEach(b => {
                bb += `{${b.toString(16).toUpperCase()}}`;
              });
              console.log(bb);*/
              //sock.write(report);
              const glen = Object.keys(gateway).length;
              console.log(
                `> [GetFriendInformation] [${csock.info.id}] : Response ${glen} friends`
              );
            } else {
              let p = {
                cmd: command.FriendInformation,
                param: {
                  Success: true,
                  Message: "",
                  Member: [],
                },
              };
              csock.socket.send(JSON.stringify(p));
              console.log(
                `> [GetFriendInformation] [${csock.info.id}] : Response 0 friend`
              );
            }
          })();
        }
      } else if (response.cmd == command.GetOverviews) {
        // get information
        if (csock.islogin == false) {
          //Reject command
          let p = {
            cmd: command.CommandReject,
            param: {
              Status: 0,
              Message: "Command reject",
            },
          };
          csock.timestamp = new Date();
          WebSocketAdminManager.sendLog("reject", {
            datestamp: csock.timestamp.toLocaleDateString(),
            timestamp: csock.timestamp.toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
              second: "2-digit",
              hour12: false, // 24-hour format
            }),
            cmd: admincommand.GetOverviews,
            message: `[WS]Reject ${clientIP}:${clientPort} because not login.`,
          });
          csock.socket.send(JSON.stringify(p));
        } else {
          console.log(`> [GetOverviews] [${csock.info.id}] : Request`);
          let summary = {
            totalGateway: 0,
            onlineGateway: 0,
            offlineGateway: 0,
            totalDevice: 0,
            onlineDevice: 0,
            offlineDevice: 0,
          };
          (async () => {
            // เอา memberid ไปเช็ค site_id และ เอา site_id ไป หา contreact_id เพื่อ เอาไปหา gateway อีกที
            let siteResult = await querys(
              `SELECT lmsm.site_id, lc.id AS contract_id, lg.id AS gateway_id
                FROM Lamp_Member_Site_Mapping AS lmsm
                INNER JOIN Lamp_Contracts AS lc ON lmsm.site_id = lc.site_id
                INNER JOIN Lamp_Gateways AS lg ON lc.id = lg.contract_id
                WHERE lmsm.member_id = :mid`,
              { mid: jpayload.lamp_member_id }
            );
            // console.log(siteResult?.response);
            if (siteResult.response.length > 0) {
              let memberPromises = siteResult.response.map(async (member) => {
                summary.totalGateway += 1;

                let gwsock = sockets.find(
                  (x) => x.info.id == member.gateway_id
                );
                let gwwssock = wsClient.find(
                  (x) => x.info.id == member.gateway_id
                );

                summary.onlineGateway +=
                  (gwsock != undefined && gwsock.islogin == true) ||
                  (gwwssock != undefined && gwwssock.islogin == true)
                    ? 1
                    : 0;
                summary.offlineGateway =
                  summary.totalGateway - summary.onlineGateway;

                let deviceResult = await querys(
                  `SELECT dev.MemberID, dev.DeviceID, dev.DeviceStyleID, devc.ControlID, devc.LastValue
                FROM Devices AS dev
                INNER JOIN DevicetControl AS devc ON dev.MemberID = devc.MemberID AND dev.DeviceID = devc.DeviceID 
                AND dev.DeviceStyleID = 3 AND devc.ControlID = 0
                WHERE dev.MemberID = :mid`,
                  { mid: member.gateway_id }
                );
                if (deviceResult.response.length > 0) {
                  let devicePromises = deviceResult.response.map(
                    async (device) => {
                      summary.totalDevice += 1;
                      summary.onlineDevice += device.LastValue == 1 ? 1 : 0;
                      summary.offlineDevice =
                        summary.totalDevice - summary.onlineDevice;
                    }
                  );
                  await Promise.all(devicePromises);
                }
              });
              await Promise.all(memberPromises);
              let p = {
                cmd: command.GetOverviews,
                param: {
                  Success: true,
                  Message: "",
                  Overviews: summary,
                },
              };
              csock.socket.send(JSON.stringify(p));
              console.log(
                `> [GetOverviews] [${
                  csock.info.id
                }] : Response ${JSON.stringify(summary)}`
              );
            } else {
              let p = {
                cmd: command.GetOverviews,
                param: {
                  Success: true,
                  Message: "Not site found",
                },
              };
              csock.socket.send(JSON.stringify(p));
              console.log(
                `> [GetOverviews] [${
                  csock.info.id
                }] : Response ${JSON.stringify(summary)}`
              );
            }
          })();
        }
      }
    }
    //verifyPacketWebsocket(message);
  });

  ws.on("error", function error(err) {
    console.log(`> [WS.Error] ${err}`);
  });
  ws.on("close", function close() {
    //console.log("disconnected");
    let index = wsClient.findIndex(function (o) {
      return o.id == csock.id;
    });

    csock.timestamp = new Date();
    WebSocketAdminManager.clientDisconnect("ws", csock.id);
    if (index != -1) {
      WebSocketAdminManager.sendLog("disconnect", {
        datestamp: csock.timestamp.toLocaleDateString(),
        timestamp: csock.timestamp.toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
          hour12: false, // 24-hour format
        }),
        cmd: admincommand.Disconnect,
        message: `[WS][${csock.info.id}] ${csock.info.name} Disconnected`,
      });
      if (wsClient[index].islogin == true) {
        console.log(
          `> [Client] [${wsClient[index].info.name} - ${clientIP}:${clientPort}] Disconnected.`
        );
        if (wsClient[index].info.role != deviceType.User) {
          let p = {
            MemberID: wsClient[index].info.id,
            Status: 0,
          };
          let getf = getMyfriend(wsClient[index]);
          if (getf != undefined) {
            getf.tcp.forEach((frd) => {
              sendToMyFriendTCP(command.FriendStatus, p, frd);
            });
            getf.ws.forEach((frd) => {
              sendToMyFriendWS(command.FriendStatus, p, frd);
            });
          }
        }
      } else {
        console.log(`> [Client] [${clientIP}:${clientPort}] Disconnected.`);
      }

      wsClient.splice(index, 1);
    } else {
      console.log(`> [Client] [${clientIP}:${clientPort}] Disconnected.`);
      WebSocketAdminManager.sendLog("disconnect", {
        datestamp: csock.timestamp.toLocaleDateString(),
        timestamp: csock.timestamp.toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
          hour12: false, // 24-hour format
        }),
        cmd: admincommand.Disconnect,
        message: `[WS]${clientIP}:${clientPort} Disconnected`,
      });
    }

    if (anonymousTimeout != null || anonymousTimeout != undefined) {
      clearTimeout(anonymousTimeout);
      anonymousTimeout = null;
    }
    //clearTimeout(pongTimeout);
    //pongTimeout = null;
    //clearInterval(pingInterval);
    //pingInterval = null;
  });

  let report = {
    status: 1,
    message: "Welcome to IoT Server. Please verify yourself.",
  };

  ws.send(JSON.stringify(report));
});

// Start the Websocket server
server.listen(process.env.WS_PORT, function () {
  console.log("[WS] Server is listening on port ", process.env.WS_PORT);
});

// [TCP Server] //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
const net = require("net");
const { default: Message } = require("tedious/lib/message");
const { promises } = require("dns");
const { DateTime } = require("mssql");
const { admincommand } = require("./models/admincommon");
const { json } = require("sequelize");
const port = process.env.TCP_PORT;
const host = "0.0.0.0";

const tcpserver = net.createServer();
tcpserver.listen(port, host, () => {
  console.log("[TCP] TCP Server is running on port " + port + ".");
});

let sockets = [];

WebSocketAdminManager.socketClient.tcp = sockets;
tcpserver.on("connection", function (sock) {
  const clientIP = sock.remoteAddress;
  const clientPort = sock.remotePort;
  //console.log("CONNECTED: " + sock.remoteAddress + ":" + sock.remotePort);
  console.log(
    `> [Client] [${sock.remoteAddress}:${sock.remotePort}] Connected.`
  );
  let csock = {
    id: uuidv4(),
    buffer: new Uint16Array(),
    lastTimestamp: new Date().getTime(),
    timestamp: new Date(),
    socket: sock,
    info: {
      id: 0,
      name: "",
      role: deviceType.Undefind,
      friend: [], //{MemberID, Role}
      friendLamp: [],
    },
    islogin: false,
  };

  sockets.push(csock);
  WebSocketAdminManager.clientConnect("tcp", csock);

  WebSocketAdminManager.sendLog("connect", {
    datestamp: csock.timestamp.toLocaleDateString(),
    timestamp: csock.timestamp.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false, // 24-hour format
    }),
    cmd: admincommand.Connect,
    message: `[TCP]${sock.remoteAddress}:${sock.remotePort}`,
  });

  //if client inactive
  let anonymousTimeout = setTimeout(function () {
    console.log(
      `> [Client] [${sock.remoteAddress}:${sock.remotePort}] timeout`
    );
    let pr = {
      Message: "Inactive disconnect!",
    };
    const report = sendPacket(command.ServerMessage, JSON.stringify(pr));
    sock.write(report);
    //Kick client
    sock.destroy();
  }, anonymousTime);

  //Ping packet to client
  let pongTimeout = null;
  let pingInterval = setInterval(function () {
    if (csock.islogin == true) {
      //let p = { p: 'pi' };
      let p = generateRandomString();
      const report = sendPacket(command.Ping, p);
      console.log(`Ping send : ${p}`);
      sock.write(report);
      //console.log(`> [Ping] Send ping to [${csock.info.name}]`);
      //console.log(pongTimeout);
      //if timeout handle client(Disconnect)
      if (pongTimeout == null) {
        pongTimeout = setTimeout(function () {
          console.log(`> [Pong] [${csock.info.name}] Pong timeout`);
          let pr = {
            Message: "Pong timeout. Will close your connection.",
          };
          const pongreport = sendPacket(
            command.ServerMessage,
            JSON.stringify(pr)
          );
          sock.write(pongreport);
          //Disconnect client
          csock.socket.destroy();
        }, pongIntervalTime);
      }
    }
  }, pingIntervalTime);
  // Handle error events, including ECONNRESET
  sock.on("error", (err) => {
    if (err.code === "ECONNRESET") {
      console.log(
        "Connection reset by peer (client disconnected unexpectedly)"
      );
    } else {
      console.error("Socket error:", err);
    }
  });
  sock.on("data", function async(data) {
    //console.log("DATA " + sock.remoteAddress + ": " + data);
    //max 32965
    // console.log(data);
    const buff = new Uint16Array(data);
    let tstp = new Date().getTime();
    if (tstp - csock.lastTimestamp > 2000) {
      //2Sec, Clear and add new buffer
      csock.buffer = buff;
    } else {
      if (csock.buffer.length > 0) {
        let combinedArray = new Uint16Array(csock.buffer.length + buff.length);
        combinedArray.set(csock.buffer, 0);
        combinedArray.set(buff, csock.buffer.length);

        csock.buffer = combinedArray;

        console.log(
          `> [Packet invalid], try append packet ------ [${csock.info.name}] : "${data}"`
        );
      } else {
        csock.buffer = buff;
        //console.log(`add packet`);
      }
    }
    csock.lastTimestamp = tstp;

    if (csock.buffer.length < minimumPacket) {
      return;
    }

    /*
      //0x22 = ' " '
      let endJ = csock.buffer.findIndex(x => x == 0x7D); //Find '}'
      console.log(`endJ: ${endJ}`);

      if (csock.buffer.length > endJ + 1) {

      }
    */

    //split packet

    const responses = verifyMultiPacket(csock.buffer);
    csock.buffer = responses.remainingbuffer;
    //const responses = verifyPacket(csock.buffer);
    responses.packet.forEach((response) => {
      console.log(
        `Gateway sedn :::::::::::::::::::::::::::::::::: ${JSON.stringify(
          response
        )}`
      );
      // if (response.cmd == -1) {
      //   //console.log(`cmd: ${response.cmd}/res: ${response.payload}`);
      // }
      // else {
      //   csock.buffer = new Uint16Array();
      //   //console.log(`cmd: ${response.cmd}/res: ${response.payload}`);
      // }

      //console.log(buff);
      //const res = verifyPacket(buff);//{ cmd, payload, packet, length }
      //console.log(payload);

      let jpayload = null;

      //let jpayload = JSON.parse(payload);
      //console.log(`verifyPacket cmd:${cmd}, length:${length}, payload:${payload}`);
      //if (response.cmd == -1) {
      //  console.log(`> [Payload] : ${response.payload}`);
      //}
      /*else if (cmd == -2) {
        console.log(`> [Payload] : packet : ${packet}`);
        csock.buffer = buff;
        //csock.buffer = new Uint16Array(buffer, 2, 4);
        let combinedArray = new Uint16Array(csock.buffer.length + buff.length);
        combinedArray.set(csock.buffer, 0);
        combinedArray.set(buff, csock.buffer.length);
        csock.buffer = combinedArray;
        console.log(combinedArray);
  
      }*/
      //else
      if (response.cmd > 0) {
        //csock.buffer = new Uint16Array();
        if (
          response.cmd != command.Logout &&
          response.cmd != command.Ping &&
          response.cmd != command.Pong
        ) {
          if (response.payload) {
            try {
              jpayload = JSON.parse(response.payload);
            } catch (err) {
              console.log(
                `> [Error] Payload JSON.parse.Error : ${err} (${JSON.stringify(
                  response.payload
                )})`
              );
              return;
            }
          }
        }

        if (response.cmd == command.Login) {
          //Login
          //01 33 01 00 7b 22 55 73 65 72 6e 61 6d 65 22 3a 22 68 61 6d 22 2c 22 50 61 73 73 77 6f 72 64 22 3a 22 31 32 33 34 35 36 22 2c 22 54 6f 6b 65 6e 22 3a 22 22 7d

          //{01}{7A}{01}{00}{7B}{22}{53}{75}{63}{63}{65}{73}{73}{22}{3A}{74}{72}{75}{65}{2C}{22}{4D}{65}{6D}{62}{65}{72}{49}{44}{22}{3A}{32}{2C}{22}{4E}{61}{6D}{65}{22}{3A}{22}{4E}{6F}{74}{74}{69}{6E}{67}{48}{61}{6D}{20}{53}{6D}{69}{74}{68}{20}{41}{6C}{6C}{79}{22}{2C}{22}{44}{65}{76}{69}{63}{65}{54}{79}{70}{65}{22}{3A}{31}{2C}{22}{53}{74}{61}{74}{75}{73}{22}{3A}{30}{2C}{22}{4D}{65}{73}{73}{61}{67}{65}{22}{3A}{22}{57}{65}{6C}{63}{6F}{6D}{65}{20}{74}{6F}{20}{49}{4F}{54}{20}{53}{65}{72}{76}{65}{72}{22}{7D}
          //{"Success":true,"MemberID":2,"Name":"NottingHam Smith Ally","DeviceType":1,"Status":0,"Message":"Welcome to IOT Server"}

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
                  bcrypt.compare(
                    jpayload.Password,
                    member.Password,
                    function (err, result) {
                      if (err) {
                        console.log(`Crypto.Error : ${err}`);
                      } else {
                        console.log(
                          `> [Auth] [${member.MemberName}] Authentication : ${result}`
                        );
                        if (result == true) {
                          //console.log(`Login : ${sock.remoteAddress}:${sock.remotePort}`);
                          //Stop kick inactive client
                          clearTimeout(anonymousTimeout);
                          anonymousTimeout = null;

                          console.log(
                            `> [Client] [${csock.socket.remoteAddress}:${csock.socket.remotePort} is ${member.MemberName}]`
                          );

                          let p = {
                            Success: true,
                            MemberID: member.MemberID,
                            Name: `${member.MemberName}`,
                            DeviceType: member.DeviceType,
                            Status: loginStatus.Success,
                            Message: "Welcome to IOT Server",
                          };
                          csock.info.role =
                            member.DeviceType == 1
                              ? deviceType.User
                              : member.DeviceType == 2
                              ? deviceType.Device
                              : deviceType.DeviceByteArray;
                          csock.islogin = true;
                          //console.log(`sock : ${JSON.stringify(csock.info)}`);
                          csock.info.id = member.MemberID;
                          csock.info.name = member.MemberName;
                          //console.log(`sock : ${JSON.stringify(csock.info)}`);

                          //let soc = sockets.find(item => item.socket === sock);
                          //console.log(`sock : ${JSON.stringify(soc.info)}`);

                          const report = sendPacket(
                            command.Login,
                            JSON.stringify(p)
                          );
                          sock.write(report);

                          //if member is Device, Then get friend list
                          if (csock.info.role != deviceType.User) {
                            //Get friend
                            (async () => {
                              let friendResult = await querys(
                                "SELECT * FROM Friends WHERE Friend = :fid",
                                { fid: csock.info.MemberID }
                              );
                              if (friendResult.response.length > 0) {
                                let friendPromises = friendResult.response.map(
                                  async (friend) => {
                                    console.log(friend);
                                    if (friend != undefined) {
                                      let fr = {
                                        memberID: friend.MemberID,
                                        role: friend.FRID,
                                      };
                                      csock.info.friend.push(fr);
                                      //console.log(fr);
                                      //---------------------------------------------------------------------------------
                                      console.log(
                                        `> [Device Status] [${gwmem.MemberName}] Online`
                                      );
                                      //Broadcast to friend user
                                      let p = {
                                        MemberID: gwmem.MemberID,
                                        Status: 1,
                                      };
                                      sendToMyFriend(
                                        command.FriendStatus,
                                        p,
                                        friend.MemberID
                                      );

                                      //----------------------------------------------------------------------------------
                                    }
                                  }
                                );
                                await Promise.all(friendPromises); // Wait for all friend queries
                              }
                            })();
                          }
                          WebSocketAdminManager.clientUpdateInfo("tcp", csock);
                          csock.timestamp = new Date();
                          WebSocketAdminManager.sendLog("login", {
                            datestamp: csock.timestamp.toLocaleDateString(),
                            timestamp: csock.timestamp.toLocaleTimeString([], {
                              hour: "2-digit",
                              minute: "2-digit",
                              second: "2-digit",
                              hour12: false, // 24-hour format
                            }),
                            cmd: admincommand.Login,
                            message: `[TCP]${clientIP}:${clientPort} as [${member.MemberID}] ${member.MemberName}`,
                          });
                        } else {
                          //{"Success":false,"MemberID":0,"Name":"","DeviceType":0,"Status":1,"Message":"password is invalid"}
                          let p = {
                            Success: false,
                            MemberID: 0,
                            Name: "",
                            DeviceType: 0,
                            Status: loginStatus.WrongUsernameOrPassword,
                            Message: "password is invalid",
                          };
                          const report = sendPacket(
                            command.Login,
                            JSON.stringify(p)
                          );
                          sock.write(report);
                        }
                      }
                    }
                  );
                  //console.log(`Member found: ${JSON.stringify(member)}`);
                } else {
                  //{"Success":false,"MemberID":0,"Name":"","DeviceType":0,"Status":1,"Message":"password is invalid"}
                  let p = {
                    Success: false,
                    MemberID: 0,
                    Name: "",
                    DeviceType: 0,
                    Status: loginStatus.WrongUsernameOrPassword,
                    Message: "Username not found.",
                  };
                  const report = sendPacket(command.Login, JSON.stringify(p));
                  sock.write(report);
                  //console.log(`No member found with username: ${jpayload.Username}`);
                }
              } catch (error) {
                console.error(`> [Error] fetching member: ${error.message}`);
              }
            })(); // Invoke the async function
          } else if (jpayload.Token) {
            //console.log(`Token : ${jpayload.Token}`);
            // Get devices
            (async () => {
              let tokenResult = await querys(
                "SELECT TOP(1) * FROM MemberTokenLogin WHERE Token = :token",
                { token: jpayload.Token }
              );
              //console.log(`tokenResult : ${tokenResult.response.length}`);
              if (tokenResult.response.length > 0) {
                let tokenPromises = tokenResult.response.map(async (token) => {
                  if (token != undefined) {
                    let memId = token.MemberID;
                    let expire = token.Expire;
                    let memberResult = await querys(
                      "SELECT TOP(1) * FROM Member WHERE MemberID = :mid",
                      { mid: memId }
                    );
                    //console.log(memberResult);
                    if (memberResult.response.length > 0) {
                      let memberPromises = memberResult.response.map(
                        async (gwmem) => {
                          //console.log(gwmem);
                          if (gwmem != undefined) {
                            //Stop kick inactive client
                            clearTimeout(anonymousTimeout);
                            anonymousTimeout = null;

                            //Check client dupplicate
                            let cdup = sockets.find(
                              (x) => x.info.id == gwmem.MemberID
                            );

                            let wscdup = wsClient.find(
                              (x) => x.info.id == gwmem.MemberID
                            );
                            if (cdup == undefined && wscdup == undefined) {
                              console.log(
                                `> [Client] [${csock.socket.remoteAddress}:${csock.socket.remotePort} is ${gwmem.MemberName}]`
                              );
                              let p = {
                                Success: true,
                                MemberID: gwmem.MemberID,
                                Name: `${gwmem.MemberName}`,
                                DeviceType: gwmem.DeviceType,
                                Status: loginStatus.Success,
                                Message: "Welcome to IOT Server",
                              };
                              csock.info.role =
                                gwmem.DeviceType == 1
                                  ? deviceType.User
                                  : gwmem.DeviceType == 2
                                  ? deviceType.Device
                                  : deviceType.DeviceByteArray;
                              csock.islogin = true;
                              //console.log(`sock : ${JSON.stringify(csock.info)}`);
                              csock.info.id = gwmem.MemberID;
                              csock.info.name = gwmem.MemberName;
                              //console.log(`sock : ${JSON.stringify(csock.info)}`);

                              //let soc = sockets.find(item => item.socket === sock);
                              //console.log(`sock : ${JSON.stringify(soc.info)}`);

                              const report = sendPacket(
                                command.Login,
                                JSON.stringify(p)
                              );
                              sock.write(report);

                              //console.log(`> [Device Status] [${gwmem.MemberName}] Online`);
                              //if member is Device, Then get friend list
                              if (csock.info.role != deviceType.User) {
                                //Get friend
                                let friendResult = await querys(
                                  "SELECT * FROM Friends WHERE Friend = :fid",
                                  { fid: gwmem.MemberID }
                                );
                                //console.log(memberResult);
                                if (friendResult.response.length > 0) {
                                  let friendPromises =
                                    friendResult.response.map(
                                      async (friend) => {
                                        //console.log(friend);
                                        if (friend != undefined) {
                                          let fr = {
                                            memberID: friend.MemberID,
                                            role: friend.FRID,
                                          };
                                          csock.info.friend.push(fr);
                                          //console.log(fr);
                                          //---------------------------------------------------------------------------------

                                          //Broadcast to friend user
                                          let p = {
                                            MemberID: gwmem.MemberID,
                                            Status: 1,
                                          };
                                          sendToMyFriend(
                                            command.FriendStatus,
                                            p,
                                            friend.MemberID
                                          );
                                          //----------------------------------------------------------------------------------
                                        }
                                      }
                                    );
                                  await Promise.all(friendPromises); // Wait for all friend queries
                                }
                                // ----------------- send to client is friend is site ----------------------------------
                                let gatewayResult = await querys(
                                  `SELECT lg.id AS gateway_id
                                    FROM Lamp_Gateways AS lg
                                    WHERE  lg.id = :mid`,
                                  { mid: gwmem.MemberID }
                                );
                                if (gatewayResult.response.length > 0) {
                                  let gatewayPromises =
                                    gatewayResult.response.map(
                                      async (gateway) => {
                                        if (gateway != undefined) {
                                          let friendLampResult = await querys(
                                            "SELECT * FROM Friends WHERE Friend = :fid",
                                            { fid: gateway.gateway_id }
                                          );
                                          if (
                                            friendLampResult.response.length > 0
                                          ) {
                                            let friendPromisesLamp =
                                              friendLampResult.response.map(
                                                async (friend) => {
                                                  //console.log(friend);
                                                  if (friend != undefined) {
                                                    let fr = {
                                                      memberID: friend.MemberID,
                                                      role: friend.FRID,
                                                    };
                                                    csock.info.friendLamp.push(
                                                      fr
                                                    );
                                                    //Broadcast to friend user
                                                    let p = {
                                                      MemberID: gwmem.MemberID,
                                                      DeviceID: null,
                                                      Type: "gateway",
                                                      Status: 1,
                                                    };
                                                    sendToMyFriend(
                                                      command.UpdateOverviews,
                                                      p,
                                                      friend.MemberID
                                                    );
                                                    //----------------------------------------------------------------------------------
                                                  }
                                                }
                                              );
                                            await Promise.all(
                                              friendPromisesLamp
                                            );
                                          }
                                        }
                                      }
                                    );
                                  await Promise.all(gatewayPromises);
                                }
                              }
                              WebSocketAdminManager.clientUpdateInfo(
                                "tcp",
                                csock
                              );

                              csock.timestamp = new Date();
                              WebSocketAdminManager.sendLog("login", {
                                datestamp: csock.timestamp.toLocaleDateString(),
                                timestamp: csock.timestamp.toLocaleTimeString(
                                  [],
                                  {
                                    hour: "2-digit",
                                    minute: "2-digit",
                                    second: "2-digit",
                                    hour12: false, // 24-hour format
                                  }
                                ),
                                cmd: admincommand.Login,
                                message: `[TCP]${sock.remoteAddress}:${sock.remotePort} as [${gwmem.MemberID}] ${gwmem.MemberName}`,
                              });
                            } else {
                              //Reject command
                              let p = {
                                Status: 0,
                                Message: "Command reject, (Dupplicate login)",
                              };
                              const report = sendPacket(
                                command.CommandReject,
                                JSON.stringify(p)
                              );
                              sock.write(report);
                              sock.destroy();
                            }
                          }
                        }
                      );
                      await Promise.all(memberPromises); // Wait for all device queries
                    }
                  }
                });
                await Promise.all(tokenPromises); // Wait for all device queries
              }
            })();
          } else {
            console.log("> [Auth} Username is undefined or null");
          }
        } else if (response.cmd == command.Logout) {
          //Logout
          if (csock.islogin == false) {
            //Reject command
            let p = {
              Status: 0,
              Message: "Command reject",
            };
            const report = sendPacket(command.CommandReject, JSON.stringify(p));
            sock.write(report);
            csock.timestamp = new Date();
            WebSocketAdminManager.sendLog("reject", {
              datestamp: csock.timestamp.toLocaleDateString(),
              timestamp: csock.timestamp.toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
                hour12: false, // 24-hour format
              }),
              cmd: admincommand.Logout,
              message: `[TCP]Reject ${clientIP}:${clientPort} because not login.`,
            });
          } else {
            clearInterval(pingInterval);
            console.log(
              `> [Client] [${csock.info.name} - ${sock.remoteAddress}:${sock.remotePort}] Logout`
            );
          }
        } else if (response.cmd == command.Ping) {
          //console.log(`Ping : ${payload}`);
        } else if (response.cmd == command.Pong) {
          console.log(`> [Pong] [${csock.info.name}] pong response`);
          clearTimeout(pongTimeout);
          pongTimeout = null;
        } else if (response.cmd == command.Logs) {
          // [TCP] Logs, From gateway to user
          if (csock.islogin == false) {
            //Reject command
            let p = {
              Status: 0,
              Message: "Command reject",
            };
            console.log(p);
            const report = sendPacket(command.Logs, JSON.stringify(p));
            sock.write(report);
            csock.timestamp = new Date();
            // WebSocketAdminManager.sendLog("reject", {
            //   datestamp: csock.timestamp.toLocaleDateString(),
            //   timestamp: csock.timestamp.toLocaleTimeString([], {
            //     hour: "2-digit",
            //     minute: "2-digit",
            //     second: "2-digit",
            //     hour12: false, // 24-hour format
            //   }),
            //   cmd: admincommand.Logs,
            //   message: `[TCP]Reject ${clientIP}:${clientPort} - [Device ${jpayload.device_id}] because not login.`,
            // });
          } else {
            // {"cmd":50,"payload":"{"transaction":"46","device_id":"201","c10":"80","c11":"24","c12":"0","c13":"220","c14":"1200","c15":"230","c16":"1500","c17":"15","c18":"80","c19":"95","c20:":"4560","timestamp:":"20250919 172030"}"}
            console.log(
              `> [Logs] From [${csock.info.id}] : ${JSON.stringify(jpayload)}`
            );

            (async () => {
              let isGateway = await excutes(
                `SELECT lc.site_id, lg.id AS gateway_id, lg.gateway_name 
                  FROM Lamp_Gateways lg
                  JOIN Lamp_Contracts lc ON lg.contract_id = lc.id
                  WHERE lg.id = :gateway_id`,
                {
                  gateway_id: csock.info.id,
                }
              );
              if (isGateway.response[0].length > 0) {
                const detail = {
                  gateway_id: csock.info.id,
                  device_id: jpayload.device_id,
                  input: {
                    volt: jpayload.c13,
                    current: jpayload.c14,
                  },
                  output: {
                    volt: jpayload.c15,
                    current: jpayload.c16,
                  },
                  battery: {
                    batt_volt: jpayload.c17,
                    capacity: jpayload.c18,
                    health: jpayload.c19,
                    cycle: jpayload.c20,
                    level: jpayload.c10,
                    charge: jpayload.c12,
                  },
                  env: { temp: jpayload.c11, humid: 0 },
                  timestamp: convert(jpayload.timestamp),
                };

                const payload_detail = {
                  type: "log",
                  detail: JSON.stringify([detail]),
                  control_by: csock.info.id,
                  site_id: isGateway.response[0][0].site_id,
                };
                const d = new Date();
                await excutes(
                  `INSERT INTO Lamp_Log (type, detail, control_by, created_at, site_id)
                   VALUES (:type, :detail, :control_by, :created_at, :site_id)`,
                  {
                    type: payload_detail.type,
                    detail: payload_detail.detail,
                    control_by: payload_detail.control_by,
                    created_at: d.toISOString().slice(0, 23).replace("T", " "),
                    site_id: payload_detail.site_id,
                  }
                );
                console.log(
                  `> [Logs] Insert Logs [${csock.info.id}] : Device - ${jpayload.device_id}`
                );
                let p = {
                  log_type: "log",
                  gateway_id: csock.info.id,
                  device_id: device_id,
                  input: {
                    volt: jpayload.c13,
                    current: jpayload.c14,
                  },
                  output: {
                    volt: jpayload.c15,
                    current: jpayload.c16,
                  },
                  battery: {
                    batt_volt: jpayload.c17,
                    capacity: jpayload.c18,
                    health: jpayload.c19,
                    cycle: jpayload.c20,
                    level: jpayload.c10,
                    charge: jpayload.c12,
                  },
                  env: { temp: jpayload.c11, humid: 0 },
                  created_at: d.toISOString().slice(0, 23).replace("T", " "),
                };
                sendPacket(
                  command.Logs,
                  JSON.stringify({
                    transaction: jpayload.transaction,
                    device_id: jpayload.device_id,
                  })
                );
                let getf = getMyfriend(csock);
                if (getf != undefined) {
                  getf.tcp.forEach((frd) => {
                    sendToMyFriendTCP(command.Logs, p, frd);
                  });
                  getf.ws.forEach((frd) => {
                    sendToMyFriendWS(command.Logs, p, frd);
                  });
                }
                csock.timestamp = new Date();
              }
            })();
          }
        } else if (response.cmd == command.Configuration) {
          //Config, From user to gateway
          if (csock.islogin == false) {
            //Reject command
            let p = {
              Status: 0,
              Message: "Command reject",
            };
            const report = sendPacket(command.CommandReject, JSON.stringify(p));
            sock.write(report);
            csock.timestamp = new Date();
            WebSocketAdminManager.sendLog("reject", {
              datestamp: csock.timestamp.toLocaleDateString(),
              timestamp: csock.timestamp.toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
                hour12: false, // 24-hour format
              }),
              cmd: command.Configuration,
              message: `[TCP]Reject ${clientIP}:${clientPort} - [${jpayload.Member}] because not login.`,
            });
          } else {
            if (csock.info.role != deviceType.User) {
              let p = {
                Status: 0,
                Message: "Command reject, Device cannot config device.",
              };
              console.log(p);
              const report = sendPacket(
                command.CommandReject,
                JSON.stringify(p)
              );
              sock.write(report);
              csock.timestamp = new Date();
              WebSocketAdminManager.sendLog("reject", {
                datestamp: csock.timestamp.toLocaleDateString(),
                timestamp: csock.timestamp.toLocaleTimeString([], {
                  hour: "2-digit",
                  minute: "2-digit",
                  second: "2-digit",
                  hour12: false, // 24-hour format
                }),
                cmd: command.Configuration,
                message: `[TCP]Reject[${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [${jpayload.Member}] because Device cannot config device.`,
              });
            } else {
              console.log(
                `> [Config] From [${csock.info.id}] : ${JSON.stringify(
                  jpayload
                )}`
              );

              //let payloadString = payload.toString('utf-8');

              let gw = sockets.find((x) => x.info.id == jpayload.Member);
              let wsgw = wsClient.find((x) => x.info.id == jpayload.Member);

              if (gw != undefined) {
                //console.log(`Gateway : [${gw.info.name}]`);
                //Get friend right
                let myFriend = gw.info.friend.find(
                  (x) => x.memberID == csock.info.id
                );
                if (myFriend != undefined) {
                  //console.log(`myFriend : ${myFriend.memberID}`);
                  if (
                    myFriend.role != friendRight.DeviceMonitor &&
                    myFriend.role != friendRight.NotFriend
                  ) {
                    //Grant Control

                    let p = {
                      Member: jpayload.Member,
                      config: jpayload,
                    };
                    const report = sendPacket(
                      command.Configuration,
                      JSON.stringify(p)
                    );
                    gw.socket.write(report);
                    csock.timestamp = new Date();
                    WebSocketAdminManager.sendLog("config", {
                      datestamp: csock.timestamp.toLocaleDateString(),
                      timestamp: csock.timestamp.toLocaleTimeString([], {
                        hour: "2-digit",
                        minute: "2-digit",
                        second: "2-digit",
                        hour12: false, // 24-hour format
                      }),
                      cmd: command.Configuration,
                      message: `[WS][${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [Member: ${jpayload.Member}]`,
                    });
                    /*
                    let p = {
                      Member: jpayload.Member,
                      Device: jpayload.Device,
                      Ctrl: jpayload.Ctrl,
                      V: jpayload.V,
                      R: jpayload.R
                    };
                    const report = sendPacket(command.DeviceUpdateValue, JSON.stringify(p));
                    sock.write(report);*/
                  } else {
                    //cannot control, No permission
                    let p = {
                      Status: 0,
                      Message: "Command reject, Cannot config. Monitor only.",
                    };
                    console.log(p);
                    const report = sendPacket(
                      command.CommandReject,
                      JSON.stringify(p)
                    );
                    sock.write(report);
                    csock.timestamp = new Date();
                    WebSocketAdminManager.sendLog("reject", {
                      datestamp: csock.timestamp.toLocaleDateString(),
                      timestamp: csock.timestamp.toLocaleTimeString([], {
                        hour: "2-digit",
                        minute: "2-digit",
                        second: "2-digit",
                        hour12: false, // 24-hour format
                      }),
                      cmd: command.Configuration,
                      message: `[TCP]Reject[${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [${jpayload.Member}] because Cannot config. Monitor only.`,
                    });
                  }
                } else {
                  let p = {
                    Status: 0,
                    Message: "Command reject, No permission.",
                  };
                  console.log(p);
                  const report = sendPacket(
                    command.CommandReject,
                    JSON.stringify(p)
                  );
                  sock.write(report);
                  csock.timestamp = new Date();
                  WebSocketAdminManager.sendLog("reject", {
                    datestamp: csock.timestamp.toLocaleDateString(),
                    timestamp: csock.timestamp.toLocaleTimeString([], {
                      hour: "2-digit",
                      minute: "2-digit",
                      second: "2-digit",
                      hour12: false, // 24-hour format
                    }),
                    cmd: command.Configuration,
                    message: `[TCP]Reject[${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [${jpayload.Member}] because No permission.`,
                  });
                }
              } else if (wsgw != undefined) {
                //console.log(`Gateway : [${gw.info.name}]`);
                //Get friend right
                let myFriend = wsgw.info.friend.find(
                  (x) => x.memberID == csock.info.id
                );
                if (myFriend != undefined) {
                  //console.log(`myFriend : ${myFriend.memberID}`);
                  if (
                    myFriend.role != friendRight.DeviceMonitor &&
                    myFriend.role != friendRight.NotFriend
                  ) {
                    //Grant Control

                    let p = {
                      cmd: command.Configuration,
                      param: {
                        Member: jpayload.Member,
                        config: jpayload,
                      },
                    };
                    //const report = sendPacket(command.DeviceControl, JSON.stringify(p));
                    wsgw.socket.send(JSON.stringify(p));
                    /*
                    let p = {
                      Member: jpayload.Member,
                      Device: jpayload.Device,
                      Ctrl: jpayload.Ctrl,
                      V: jpayload.V,
                      R: jpayload.R
                    };
                    const report = sendPacket(command.DeviceUpdateValue, JSON.stringify(p));
                    sock.write(report);*/
                  } else {
                    //cannot control, No permission
                    let p = {
                      cmd: command.CommandReject,
                      param: {
                        Status: 0,
                        Message:
                          "Command reject, Cannot control. Monitor only.",
                      },
                    };
                    console.log(p);
                    //const report = sendPacket(command.CommandReject, JSON.stringify(p));
                    ws.send(JSON.stringify(p));
                    csock.timestamp = new Date();
                    WebSocketAdminManager.sendLog("reject", {
                      datestamp: csock.timestamp.toLocaleDateString(),
                      timestamp: csock.timestamp.toLocaleTimeString([], {
                        hour: "2-digit",
                        minute: "2-digit",
                        second: "2-digit",
                        hour12: false, // 24-hour format
                      }),
                      cmd: command.Configuration,
                      message: `[TCP]Reject[${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [${jpayload.Member}] because Cannot config. Monitor only.`,
                    });
                  }
                } else {
                  let p = {
                    Status: 0,
                    Message: "Command reject, No permission.",
                  };
                  console.log(p);
                  const report = sendPacket(
                    command.CommandReject,
                    JSON.stringify(p)
                  );
                  csock.socket.write(report);
                  csock.timestamp = new Date();
                  WebSocketAdminManager.sendLog("reject", {
                    datestamp: csock.timestamp.toLocaleDateString(),
                    timestamp: csock.timestamp.toLocaleTimeString([], {
                      hour: "2-digit",
                      minute: "2-digit",
                      second: "2-digit",
                      hour12: false, // 24-hour format
                    }),
                    cmd: command.Configuration,
                    message: `[TCP]Reject[${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [${jpayload.Member}] because No permission.`,
                  });
                }
                //end ws phase
              } else {
                let p = {
                  Status: 0,
                  Message:
                    "Command reject(not found target or Offline), Target not found or Offline.",
                };
                console.log(p);
                const report = sendPacket(
                  command.Configuration,
                  JSON.stringify(p)
                );
                csock.socket.write(report);
                csock.timestamp = new Date();
                WebSocketAdminManager.sendLog("config", {
                  datestamp: csock.timestamp.toLocaleDateString(),
                  timestamp: csock.timestamp.toLocaleTimeString([], {
                    hour: "2-digit",
                    minute: "2-digit",
                    second: "2-digit",
                    hour12: false, // 24-hour format
                  }),
                  cmd: command.Configuration,
                  message: `[TCP][${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [Member: ${jpayload.Member}] Target not found or Offline.`,
                });
              }
            }
          }
        } else if (response.cmd == command.DeviceControl) {
          //Control, From user to gateway
          if (csock.islogin == false) {
            //Reject command
            let p = {
              Status: 0,
              Message: "Command reject",
            };
            const report = sendPacket(command.CommandReject, JSON.stringify(p));
            sock.write(report);
            csock.timestamp = new Date();
            WebSocketAdminManager.sendLog("reject", {
              datestamp: csock.timestamp.toLocaleDateString(),
              timestamp: csock.timestamp.toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
                hour12: false, // 24-hour format
              }),
              cmd: admincommand.DeviceControl,
              message: `[TCP]Reject ${clientIP}:${clientPort} - [${jpayload.Member}:${jpayload.Device}:${jpayload.Ctrl}:${jpayload.V}] because not login.`,
            });
          } else {
            //01 36 03 00 7B 22 56 22 3A 31 2E 30 2C 22 4D 65 6D 62 65 72 22 3A 31 30 31 38 2C 22 44 65 76 69 63 65 22 3A 33 30 30 31 2C 22 43 74 72 6C 22 3A 31 2C 22 52 22 3A 30 7D
            //[Response]
            //z{"Success":false,"Message":"Member is not online, Member is not online","Member":3,"Device":3001,"Ctrl":1,"V":0.0,"R":0}
            //z{"Success":true,"Message":"Success","Member":3,"Device":3001,"Ctrl":1,"V":0.0,"R":0}
            //[Request]
            //cmd:3, length:51, payload:{"V":0.0,"Member":3,"Device":3001,"Ctrl":1,"R":0}
            //{"V":1.0,"Member":1018,"Device":3001,"Ctrl":1,"R":0}
            //8{"Member":2343,"Device":7101,"Ctrl":23,"V":57.2,"R":0}

            //let { V, Member, Device, Ctrl, R } = JSON.parse(payload);

            if (csock.info.role != deviceType.User) {
              let p = {
                Status: 0,
                Message: "Command reject, Device cannot control device.",
              };
              console.log(p);
              const report = sendPacket(
                command.CommandReject,
                JSON.stringify(p)
              );
              sock.write(report);
              csock.timestamp = new Date();
              WebSocketAdminManager.sendLog("reject", {
                datestamp: csock.timestamp.toLocaleDateString(),
                timestamp: csock.timestamp.toLocaleTimeString([], {
                  hour: "2-digit",
                  minute: "2-digit",
                  second: "2-digit",
                  hour12: false, // 24-hour format
                }),
                cmd: admincommand.DeviceControl,
                message: `[TCP]Reject[${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [${jpayload.Member}:${jpayload.Device}:${jpayload.Ctrl}:${jpayload.V}] because Device cannot control device.`,
              });
            } else {
              console.log(
                `> [Control] From [${csock.info.id}] : ${JSON.stringify(
                  jpayload
                )}`
              );

              //let payloadString = payload.toString('utf-8');

              let gw = sockets.find((x) => x.info.id == jpayload.Member);
              let wsgw = wsClient.find((x) => x.info.id == jpayload.Member);

              if (gw != undefined) {
                //console.log(`Gateway : [${gw.info.name}]`);
                //Get friend right
                let myFriend = gw.info.friend.find(
                  (x) => x.memberID == csock.info.id
                );
                if (myFriend != undefined) {
                  //console.log(`myFriend : ${myFriend.memberID}`);
                  if (
                    myFriend.role != friendRight.DeviceMonitor &&
                    myFriend.role != friendRight.NotFriend
                  ) {
                    //Grant Control

                    let p = {
                      Member: jpayload.Member,
                      Device: jpayload.Device,
                      Ctrl: jpayload.Ctrl,
                      V: jpayload.V,
                      R: jpayload.R,
                    };
                    const report = sendPacket(
                      command.DeviceControl,
                      JSON.stringify(p)
                    );
                    gw.socket.write(report);
                    csock.timestamp = new Date();
                    WebSocketAdminManager.sendLog("control", {
                      datestamp: csock.timestamp.toLocaleDateString(),
                      timestamp: csock.timestamp.toLocaleTimeString([], {
                        hour: "2-digit",
                        minute: "2-digit",
                        second: "2-digit",
                        hour12: false, // 24-hour format
                      }),
                      cmd: admincommand.DeviceControl,
                      message: `[WS][${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [Member: ${jpayload.Member}, Device: ${jpayload.Device}, Ctrl: ${jpayload.Ctrl}, V: ${jpayload.V}]`,
                    });
                    /*
                    let p = {
                      Member: jpayload.Member,
                      Device: jpayload.Device,
                      Ctrl: jpayload.Ctrl,
                      V: jpayload.V,
                      R: jpayload.R
                    };
                    const report = sendPacket(command.DeviceUpdateValue, JSON.stringify(p));
                    sock.write(report);*/
                  } else {
                    //cannot control, No permission
                    let p = {
                      Status: 0,
                      Message: "Command reject, Cannot control. Monitor only.",
                    };
                    console.log(p);
                    const report = sendPacket(
                      command.CommandReject,
                      JSON.stringify(p)
                    );
                    sock.write(report);
                    csock.timestamp = new Date();
                    WebSocketAdminManager.sendLog("reject", {
                      datestamp: csock.timestamp.toLocaleDateString(),
                      timestamp: csock.timestamp.toLocaleTimeString([], {
                        hour: "2-digit",
                        minute: "2-digit",
                        second: "2-digit",
                        hour12: false, // 24-hour format
                      }),
                      cmd: admincommand.DeviceControl,
                      message: `[TCP]Reject[${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [${jpayload.Member}:${jpayload.Device}:${jpayload.Ctrl}:${jpayload.V}] because Cannot control. Monitor only.`,
                    });
                  }
                } else {
                  let p = {
                    Status: 0,
                    Message: "Command reject, No permission.",
                  };
                  console.log(p);
                  const report = sendPacket(
                    command.CommandReject,
                    JSON.stringify(p)
                  );
                  sock.write(report);
                  csock.timestamp = new Date();
                  WebSocketAdminManager.sendLog("reject", {
                    datestamp: csock.timestamp.toLocaleDateString(),
                    timestamp: csock.timestamp.toLocaleTimeString([], {
                      hour: "2-digit",
                      minute: "2-digit",
                      second: "2-digit",
                      hour12: false, // 24-hour format
                    }),
                    cmd: admincommand.DeviceControl,
                    message: `[TCP]Reject[${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [${jpayload.Member}:${jpayload.Device}:${jpayload.Ctrl}:${jpayload.V}] because No permission.`,
                  });
                }
              } else if (wsgw != undefined) {
                //console.log(`Gateway : [${gw.info.name}]`);
                //Get friend right
                let myFriend = wsgw.info.friend.find(
                  (x) => x.memberID == csock.info.id
                );
                if (myFriend != undefined) {
                  //console.log(`myFriend : ${myFriend.memberID}`);
                  if (
                    myFriend.role != friendRight.DeviceMonitor &&
                    myFriend.role != friendRight.NotFriend
                  ) {
                    //Grant Control

                    let p = {
                      cmd: command.DeviceControl,
                      param: {
                        Member: jpayload.Member,
                        Device: jpayload.Device,
                        Ctrl: jpayload.Ctrl,
                        V: jpayload.V,
                        R: jpayload.R,
                      },
                    };
                    //const report = sendPacket(command.DeviceControl, JSON.stringify(p));
                    wsgw.socket.send(JSON.stringify(p));
                    /*
                    let p = {
                      Member: jpayload.Member,
                      Device: jpayload.Device,
                      Ctrl: jpayload.Ctrl,
                      V: jpayload.V,
                      R: jpayload.R
                    };
                    const report = sendPacket(command.DeviceUpdateValue, JSON.stringify(p));
                    sock.write(report);*/
                  } else {
                    //cannot control, No permission
                    let p = {
                      cmd: command.CommandReject,
                      param: {
                        Status: 0,
                        Message:
                          "Command reject, Cannot control. Monitor only.",
                      },
                    };
                    console.log(p);
                    //const report = sendPacket(command.CommandReject, JSON.stringify(p));
                    ws.send(JSON.stringify(p));
                    csock.timestamp = new Date();
                    WebSocketAdminManager.sendLog("reject", {
                      datestamp: csock.timestamp.toLocaleDateString(),
                      timestamp: csock.timestamp.toLocaleTimeString([], {
                        hour: "2-digit",
                        minute: "2-digit",
                        second: "2-digit",
                        hour12: false, // 24-hour format
                      }),
                      cmd: admincommand.DeviceControl,
                      message: `[TCP]Reject[${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [${jpayload.Member}:${jpayload.Device}:${jpayload.Ctrl}:${jpayload.V}] because Cannot control. Monitor only.`,
                    });
                  }
                } else {
                  let p = {
                    Status: 0,
                    Message: "Command reject, No permission.",
                  };
                  console.log(p);
                  const report = sendPacket(
                    command.CommandReject,
                    JSON.stringify(p)
                  );
                  csock.socket.write(report);
                  csock.timestamp = new Date();
                  WebSocketAdminManager.sendLog("reject", {
                    datestamp: csock.timestamp.toLocaleDateString(),
                    timestamp: csock.timestamp.toLocaleTimeString([], {
                      hour: "2-digit",
                      minute: "2-digit",
                      second: "2-digit",
                      hour12: false, // 24-hour format
                    }),
                    cmd: admincommand.DeviceControl,
                    message: `[TCP]Reject[${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [${jpayload.Member}:${jpayload.Device}:${jpayload.Ctrl}:${jpayload.V}] because No permission.`,
                  });
                }
                //end ws phase
              } else {
                let p = {
                  Status: 0,
                  Message:
                    "Command reject(not found target or Offline), Target not found or Offline.",
                };
                console.log(p);
                const report = sendPacket(
                  command.CommandReject,
                  JSON.stringify(p)
                );
                csock.socket.write(report);
                csock.timestamp = new Date();
                WebSocketAdminManager.sendLog("control", {
                  datestamp: csock.timestamp.toLocaleDateString(),
                  timestamp: csock.timestamp.toLocaleTimeString([], {
                    hour: "2-digit",
                    minute: "2-digit",
                    second: "2-digit",
                    hour12: false, // 24-hour format
                  }),
                  cmd: admincommand.DeviceControl,
                  message: `[TCP][${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [Member: ${jpayload.Member}, Device: ${jpayload.Device}, Ctrl: ${jpayload.Ctrl}, V: ${jpayload.V}] Target not found or Offline.`,
                });
              }
            }
          }
        } else if (response.cmd == command.DeviceUpdateValue) {
          // gateway update device control
          if (csock.islogin == false) {
            //Reject command
            let p = {
              Status: 0,
              Message: "Command reject",
            };
            console.log(p);
            const report = sendPacket(command.CommandReject, JSON.stringify(p));
            sock.write(report);
            csock.timestamp = new Date();
            WebSocketAdminManager.sendLog("reject", {
              datestamp: csock.timestamp.toLocaleDateString(),
              timestamp: csock.timestamp.toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
                hour12: false, // 24-hour format
              }),
              cmd: admincommand.DeviceUpdateValue,
              message: `[TCP]Reject ${clientIP}:${clientPort} - [Device ${jpayload.Device}:${jpayload.Ctrl}:${jpayload.V}] because not login.`,
            });
          } else {
            console.log(
              `> [DeviceUpdateValue] From [${csock.info.id}] : ${JSON.stringify(
                jpayload
              )}`
            );
            //Broadcast to friend user
            //csock.info.friend

            //console.log(csock.info);

            //const myFriend = getFriendOnline(csock);

            (async () => {
              let updateDeviceControlResult = await excutes(
                "UPDATE DevicetControl set LastValue = :value where MemberID = :mid and DeviceID = :did and ControlID = :ctrlid",
                {
                  value: jpayload.V,
                  mid: csock.info.id,
                  did: jpayload.Device,
                  ctrlid: jpayload.Ctrl,
                }
              );

              if (
                jpayload.Device >= 2000 &&
                jpayload.Device <= 2999 &&
                (jpayload.Ctrl === 1 || jpayload.Ctrl === 2)
              ) {
                const isGateway = await excutes(
                  `SELECT lc.site_id, lg.id AS gateway_id, lg.gateway_name 
                  FROM Lamp_Gateways lg
                  JOIN Lamp_Contracts lc ON lg.contract_id = lc.id
                  WHERE lg.id = :gateway_id`,
                  {
                    gateway_id: csock.info.id,
                  }
                );

                if (isGateway.response[0].length > 0) {
                  const payload_usage = {
                    type: "usage",
                    detail: JSON.stringify([
                      {
                        gateway_id: csock.info.id,
                        device_id: jpayload.Device,
                        control_id: jpayload.Ctrl,
                        V: jpayload.V,
                      },
                    ]),
                    control_by: csock.info.id,
                    site_id: isGateway.response[0][0].site_id,
                  };
                  // console.log(payload_usage);
                  const d = new Date();
                  const updatedLogs = await excutes(
                    `INSERT INTO Lamp_Log (type, detail, control_by, created_at, site_id)
                   VALUES (:type, :detail, :control_by, :created_at, :site_id)`,
                    {
                      type: payload_usage.type,
                      detail: payload_usage.detail,
                      control_by: payload_usage.control_by,
                      created_at: d
                        .toISOString()
                        .slice(0, 23)
                        .replace("T", " "),
                      site_id: payload_usage.site_id,
                    }
                  );
                  console.log(
                    `> [DeviceUpdateValue] Insert Log ${[
                      csock.info.id,
                    ]} : ${JSON.stringify(jpayload)}`
                  );
                }
              }
            })();

            let p = {
              Member: csock.info.id,
              Device: jpayload.Device,
              Ctrl: jpayload.Ctrl,
              V: jpayload.V,
              R: jpayload.R,
            };
            let getf = getMyfriend(csock);
            if (getf != undefined) {
              getf.tcp.forEach((frd) => {
                sendToMyFriendTCP(command.DeviceUpdateValue, p, frd);
              });
              getf.ws.forEach((frd) => {
                sendToMyFriendWS(command.DeviceUpdateValue, p, frd);
              });
            }

            if (
              jpayload.Device >= 2000 &&
              jpayload.Device <= 2999 &&
              jpayload.Ctrl == 0
            ) {
              let pl = {
                MemberID: csock.info.id,
                DeviceID: jpayload.Device,
                Type: "Device",
                Status: jpayload.V,
              };
              let getfl = getMyfriendLamp(csock);
              let sendHistory = csock.sendHistory || [];
              if (!isDuplicateSend(sendHistory, pl)) {
                getfl.tcp.forEach((frd) => {
                  sendToMyFriendTCP(command.UpdateOverviews, pl, frd);
                });
                getfl.ws.forEach((frd) => {
                  sendToMyFriendWS(command.UpdateOverviews, pl, frd);
                });
                sendHistory.push(pl);
                csock.sendHistory = sendHistory;
              }
            }

            csock.timestamp = new Date();
            WebSocketAdminManager.sendLog("control", {
              datestamp: csock.timestamp.toLocaleDateString(),
              timestamp: csock.timestamp.toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
                hour12: false, // 24-hour format
              }),
              cmd: admincommand.DeviceUpdateValue,
              message: `[TCP][${csock.info.id}]${csock.info.name} | ${clientIP}:${clientPort} - [Member: ${csock.info.id}, Device: ${jpayload.Device}, Ctrl: ${jpayload.Ctrl}, V: ${jpayload.V}]`,
            });
          }
        } else if (response.cmd == command.GetFriendInformation) {
          /* (For client)
        else if (cmd == command.FriendStatus) { // gateway online status
  
        }
        else if (cmd == command.FriendInformation) { // gateway information
  
        }*/
          // get information
          if (csock.islogin == false) {
            //Reject command
            let p = {
              Status: 0,
              Message: "Command reject",
            };
            console.log(p);
            const report = sendPacket(command.CommandReject, JSON.stringify(p));
            sock.write(report);
            csock.timestamp = new Date();
            WebSocketAdminManager.sendLog("reject", {
              datestamp: csock.timestamp.toLocaleDateString(),
              timestamp: csock.timestamp.toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
                hour12: false, // 24-hour format
              }),
              cmd: admincommand.GetFriendInformation,
              message: `[TCP]Reject ${clientIP}:${clientPort} because not login.`,
            });
          } else {
            console.log(
              `> [GetFriendInformation] [${csock.info.id}] : Request`
            );
            let gateway = {};
            (async () => {
              // Get gateway
              let memberResult = await querys(
                "SELECT Friends.MemberID as MemberID, Friends.Friend as Friend, Friends.FRID as FRID, Member.DeviceType as DeviceType, Member.MemberName as MemberName, Member.Img as Img FROM Friends inner join Member on Friends.Friend = Member.MemberID WHERE Friends.MemberID = :mid",
                { mid: csock.info.id }
              );
              if (memberResult.response.length > 0) {
                let memberPromises = memberResult.response.map(
                  async (member) => {
                    let gwsock = sockets.find(
                      (x) => x.info.id == member.Friend
                    );
                    let gwwssock = wsClient.find(
                      (x) => x.info.id == member.Friend
                    );
                    gateway[member.Friend.toString()] = {
                      Status:
                        (gwsock != undefined && gwsock.islogin == true) ||
                        (gwwssock != undefined && gwwssock.islogin == true)
                          ? 1
                          : 0,
                      Img: member.Img,
                      Name: member.MemberName,
                      DeviceType: member.DeviceType,
                      Device: {},
                    };
                    // Get devices
                    let deviceResult = await querys(
                      "SELECT * FROM Devices WHERE MemberID = :mid",
                      { mid: member.Friend }
                    );
                    if (deviceResult.response.length > 0) {
                      let devicePromises = deviceResult.response.map(
                        async (device) => {
                          gateway[member.Friend.toString()].Device[
                            device.DeviceID.toString()
                          ] = {
                            DeviceName: device.DeviceName,
                            DeviceStyleID: device.DeviceStyleID,
                            Control: {},
                          };
                          // Get control
                          let controlResult = await querys(
                            "SELECT * FROM DevicetControl WHERE MemberID = :mid and DeviceID = :did",
                            { mid: member.Friend, did: device.DeviceID }
                          );
                          if (controlResult.response.length > 0) {
                            //controlResult.response.forEach(control
                            let controlPromises = controlResult.response.map(
                              async (control) => {
                                gateway[member.Friend.toString()].Device[
                                  device.DeviceID.toString()
                                ].Control[control.ControlID.toString()] = {
                                  ControlType: control.ConTypeID,
                                  Label: control.Label,
                                  Value: control.LastValue,
                                };
                              }
                            );
                            await Promise.all(controlPromises); // Wait for all devicecontrol queries
                          }
                        }
                      );
                      await Promise.all(devicePromises); // Wait for all device queries
                    }
                  }
                );
                await Promise.all(memberPromises); // Wait for all member-related queries
                //console.log(`Gateway : ${JSON.stringify(gateway)}`);
                let p = {
                  Success: true,
                  Message: "",
                  Member: gateway,
                };
                const report = sendPacket(
                  command.FriendInformation,
                  JSON.stringify(p)
                );
                /*let bb = '';
                for (let j = 0; j < 100; j++) {
                  bb += `{${report[j].toString(16).toUpperCase()}}`;
                }
                report.forEach(b => {
                  bb += `{${b.toString(16).toUpperCase()}}`;
                });
                console.log(bb);*/
                sock.write(report);
                console.log(
                  `> [GetFriendInformation] [${csock.info.id}] : Response`
                );
              }
            })();
          }
        }
      }
    });
  });

  // Add a 'close' event handler to this instance of socket
  sock.on("close", function (data) {
    let index = sockets.findIndex(function (o) {
      return (
        o.socket.remoteAddress === sock.remoteAddress &&
        o.socket.remotePort === sock.remotePort
      );
    });

    WebSocketAdminManager.clientDisconnect("tcp", csock.id);
    if (index != -1) {
      if (sockets[index].islogin) {
        console.log(
          `> [Client] [${sockets[index].info.name} - ${clientIP}:${clientPort}] Disconnected.`
        );
        if (sockets[index].info.role != deviceType.User) {
          let p = {
            MemberID: sockets[index].info.id,
            Status: 0,
          };
          let getf = getMyfriend(sockets[index]);
          if (getf != undefined) {
            getf.tcp.forEach((frd) => {
              sendToMyFriendTCP(command.FriendStatus, p, frd);
            });
            getf.ws.forEach((frd) => {
              sendToMyFriendWS(command.FriendStatus, p, frd);
            });
          }

          let pl = {
            MemberID: sockets[index].info.id,
            DeviceID: null,
            Type: "gateway",
            Status: 0,
          };
          let getfl = getMyfriendLamp(sockets[index]);
          let sendHistory = csock.sendHistory || [];
          if (!isDuplicateSend(sendHistory, pl)) {
            getfl.tcp.forEach((frd) => {
              sendToMyFriendTCP(command.UpdateOverviews, pl, frd);
            });
            getfl.ws.forEach((frd) => {
              sendToMyFriendWS(command.UpdateOverviews, pl, frd);
            });
            sendHistory.push(pl);
            sockets[index].sendHistory = sendHistory;
          }
        }
      } else {
        console.log(`> [Client] [${clientIP}:${clientPort}] Disconnected.`);
      }

      csock.timestamp = new Date();
      WebSocketAdminManager.sendLog("disconnect", {
        datestamp: csock.timestamp.toLocaleDateString(),
        timestamp: csock.timestamp.toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
          hour12: false, // 24-hour format
        }),
        cmd: admincommand.Disconnect,
        message: `[TCP][${csock.info.id}] ${csock.info.name} (${clientIP}:${clientPort}) Disconnected`,
      });
      sockets.splice(index, 1);
    } else {
      console.log(`> [Client] [${clientIP}:${clientPort}] Disconnected.`);
      WebSocketAdminManager.sendLog("disconnect", {
        datestamp: csock.timestamp.toLocaleDateString(),
        timestamp: csock.timestamp.toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
          hour12: false, // 24-hour format
        }),
        cmd: admincommand.Disconnect,
        message: `[TCP]${clientIP}:${clientPort} Disconnected`,
      });
    }

    if (anonymousTimeout != null || anonymousTimeout != undefined) {
      clearTimeout(anonymousTimeout);
      anonymousTimeout = null;
    }
    clearTimeout(pongTimeout);
    pongTimeout = null;
    clearInterval(pingInterval);
    pingInterval = null;
  });
});
// Function to search models where role=1 and id is in the friend list
/*function getFriendOnline(models) {
  let f = [];
  models.info.friend.forEach(fr => {
    let s = sockets.find(x => x.info.id == fr.memberID)
    if (s != undefined) {
      f.push(s);
    }
  });

  return f;
}*/

///Get as Socket
function getMyfriend(_me) {
  let tcpFriend = [];
  let wsFriend = [];
  _me.info.friend.forEach((fr) => {
    let sc = sockets.filter((x) => x.info.id == fr.memberID);
    if (sc != undefined) {
      sc.forEach((s) => {
        tcpFriend.push(s);
      });
    }
    let wssc = wsClient.filter((x) => x.info.id == fr.memberID);
    if (wssc != undefined) {
      wssc.forEach((s) => {
        wsFriend.push(s);
      });
    }
  });

  return { tcp: tcpFriend, ws: wsFriend };
}
/// Get as ID
function getMyfriendID(_me) {
  let id = [];
  _me.info.friend.forEach((fr) => {
    let sc = sockets.filter((x) => x.info.id == fr.memberID);
    if (sc != undefined) {
      sc.forEach((s) => {
        const fid = id.findIndex((d) => d == s.info.id);
        console.log(`fid = ${fid}`);
        if (fid == -1) {
          id.push(s.info.id);
        }
      });
    }
    let wssc = wsClient.filter((x) => x.info.id == fr.memberID);
    if (wssc != undefined) {
      wssc.forEach((s) => {
        const fid = id.findIndex((d) => d == s.info.id);
        console.log(`fid = ${fid}`);
        if (fid == -1) {
          id.push(s.info.id);
        }
      });
    }
  });

  return id;
}

function getMyfriendLamp(_me) {
  let tcpFriend = [];
  let wsFriend = [];
  _me.info.friendLamp.forEach((fr) => {
    let sc = sockets.filter((x) => x.info.id == fr.memberID);
    if (sc != undefined) {
      sc.forEach((s) => {
        tcpFriend.push(s);
      });
    }
    let wssc = wsClient.filter((x) => x.info.id == fr.memberID);
    if (wssc != undefined) {
      wssc.forEach((s) => {
        wsFriend.push(s);
      });
    }
  });

  return { tcp: tcpFriend, ws: wsFriend };
}

function sendToMyFriendTCP(_cmd, _payload, _socket) {
  const report = sendPacket(_cmd, JSON.stringify(_payload));
  _socket.socket.write(report);
}
function sendToMyFriendWS(_cmd, _payload, _socket) {
  let wspp = {
    cmd: _cmd,
    param: _payload,
  };
  _socket.socket.send(JSON.stringify(wspp));
}
function sendToMyFriend(_cmd, _payload, _target) {
  let wspp = {
    cmd: _cmd,
    param: _payload,
  };
  const report = sendPacket(_cmd, JSON.stringify(_payload));
  let sc = sockets.filter((sof) => sof.info.id == _target);
  //console.log(`===tcp get status ${JSON.stringify(sc)}`);
  if (sc.length > 0) {
    //console.log(`===socket = ${sc.length}`);
    sc.forEach((s) => {
      //console.log(`===tcp ${s} get status`);
      s.socket.write(report);
    });
  }

  let wssc = wsClient.filter((sof) => sof.info.id == _target);
  //console.log(`===ws get status ${JSON.stringify(wssc)}`);
  if (wssc.length > 0) {
    wssc.forEach((s) => {
      //console.log(`===ws ${s} get status`);
      s.socket.send(JSON.stringify(wspp));
    });
  }
}
function sendToMySite(_cmd, payload) {}

function verifyMultiPacket(_packet) {
  //console.log("_packet : ", _packet);
  let remainingBuffer = _packet;
  let packetList = [];
  if (_packet.length > 0) {
    for (let i = 0; i < _packet.length; i++) {
      //console.log("index", i);
      let countQnt = 0; //Quantity of length byte
      let len = 0; //payload length included command 2 byte
      let lenMarker = 0;
      let cmdL = 0;
      let cmdH = 0;
      //[0x01][0xab][0x01][0x00][abcdefgh12345678]
      //[0x01][0xab][0x01][0x00][abcdefgh12345678] [0x01][0xab][0x01][0x00][abcdefgh12345678] [0x01][0xab][0x01][0x00][abcdefgh12345678]

      //Header[length quantity]
      countQnt = _packet[i]; //first byte of packet
      //Header[length]
      for (let j = 0; j < countQnt; j++) {
        len += _packet[i + 1];
        lenMarker = 1; //len=1
        if (countQnt > 1) {
          len += _packet[i + 2] * (0xff + 1);
          lenMarker = 2; //len=2
        }
        if (countQnt > 2) {
          len += _packet[i + 3] * (0xffff + 1);
          lenMarker = 3; //len=3
        }
        if (countQnt > 3) {
          len += _packet[i + 4] * (0xffffff + 1);
          lenMarker = 4; //len=4
        }
        if (countQnt > 4) {
          len += _packet[i + 5] * (0xffffffff + 1);
          lenMarker = 5; //len=5
        }
      }
      //Header [command]
      cmdL = _packet[i + countQnt + 1];
      cmdH = _packet[i + countQnt + 2];
      //Payload
      //Append payload
      //[1][quantity][2]
      //Quantity + len + cmd + (len-cmd len)
      if (i + countQnt + 2 + (len - 2) <= _packet.length) {
        //in length
        let start = i + 1 + countQnt + 2;
        let stop = i + 1 + countQnt + 2 + (len - 2);
        let pl = _packet.slice(start, stop);
        //console.log(`start : ${start}, stop : ${stop}`);
        let payload = bufferToString(pl);
        //console.log("multi : ", pl);
        //console.log("multi : ", payload);
        packetList.push({ cmd: cmdH * 256 + cmdL, payload: payload });
        i = i + countQnt + 2 + len - 2;
        remainingBuffer = _packet.slice(stop);
        //console.log(`remanining buffer : ${remainingBuffer}`);
      } else {
        //console.log("break : ");
        break;
      }
    }
  }
  let ret = { packet: packetList, remainingbuffer: remainingBuffer };
  return ret;

  let countQnt = 0; //Quantity of length byte
  let len = 0; //payload length included command 2 byte
  let cmdL = 0;
  let cmdH = 0;
  //[0x01][0xab][0x01][0x00][abcdefgh12345678]
  //[0x01][0xab][0x01][0x00][abcdefgh12345678] [0x01][0xab][0x01][0x00][abcdefgh12345678] [0x01][0xab][0x01][0x00][abcdefgh12345678]
  if (_packet.length > 0) {
    countQnt = _packet[0];
  } else {
    console.log("Payload empty.Payload empty.Payload empty.");
    //let ret = [{ cmd: -1, payload: 'Payload empty.', packet: _packet, length: 0 }];
    let ret = [];
    return ret;
  }

  if (countQnt > 0) {
    if (countQnt > _packet.length) {
      //out of length or packet invalid
      console.log("Payload invalid.---");
      let ret = [
        { cmd: -1, payload: "Payload invalid.", packet: _packet, length: 0 },
      ];
      return ret;
    } else {
      len += _packet[1];
      if (countQnt > 1) {
        len += _packet[2] * (0xff + 1);
      }
      if (countQnt > 2) {
        len += _packet[3] * (0xffff + 1);
      }
      if (countQnt > 3) {
        len += _packet[4] * (0xffffff + 1);
      }
      if (countQnt > 4) {
        len += _packet[5] * (0xffffffff + 1);
      }

      cmdL = _packet[countQnt + 1];
      cmdH = _packet[countQnt + 2];

      let buff = _packet.slice(countQnt + 3);
      //console.log(`b:${buff.length} = len:${(len - 2)}`);
      if (buff.length == len - 2) {
        //console.log("slice: " + buff);
        let payload = bufferToString(buff);
        //console.log("payload: " + payload);
        let ret = [{ cmd: cmdH * 256 + cmdL, payload: payload, length: len }];
        return ret;
      } else {
        let pg = "";
        _packet.forEach((_pg) => {
          pg += `${_pg.toString(16).toUpperCase()} `;
        });
        console.log(pg);
        let ret = [
          { cmd: -1, payload: "Payload invalid.", packet: _packet, length: 0 },
        ];
        return ret;
      }
    }
  }
}

function verifyPacket(_packet) {
  //status 1=success, 2=invalid
  //
  //const buff = new Uint16Array(data);

  /*let pg = '';
  _packet.forEach(_pg => {
    pg += `${_pg.toString(16).toUpperCase()} `;
  });
  console.log(pg);*/
  //max 32965
  let countQnt = 0; //Quantity of length byte
  let len = 0; //payload length included command 2 byte
  let cmdL = 0;
  let cmdH = 0;
  if (_packet.length > 0) {
    countQnt = _packet[0];
  } else {
    console.log("Payload invalid.Payload invalid.Payload invalid.");
    let ret = {
      status: 2,
      packet: [
        { cmd: -1, payload: "Payload invalid.", packet: _packet, length: 0 },
      ],
      remainingbuffer: null,
    };
    return ret;
  }
  //console.log(_packet[0], _packet[1], _packet[2], _packet[3], _packet[4]);
  if (countQnt > 0) {
    if (countQnt > _packet.length) {
      //out of length or packet invalid
      console.log("Payload invalid.---");
      //let ret = [{ cmd: -1, payload: 'Payload invalid.', packet: _packet, length: 0 }];
      let ret = { status: 2, packet: [], remainingbuffer: _packet };
      return ret;
    } else {
      len += _packet[1];
      if (countQnt > 1) {
        len += _packet[2] * (0xff + 1);
      }
      if (countQnt > 2) {
        len += _packet[3] * (0xffff + 1);
      }
      if (countQnt > 3) {
        len += _packet[4] * (0xffffff + 1);
      }
      if (countQnt > 4) {
        len += _packet[5] * (0xffffffff + 1);
      }

      cmdL = _packet[countQnt + 1];
      cmdH = _packet[countQnt + 2];

      let buff = _packet.slice(countQnt + 3);
      //console.log(`b:${buff.length} = len:${(len - 2)}`);
      if (buff.length == len - 2) {
        //console.log("slice: " + buff);
        let payload = bufferToString(buff);
        //console.log("payload: " + payload);
        let ret = {
          status: 1,
          packet: [{ cmd: cmdH * 256 + cmdL, payload: payload, length: len }],
          remainingbuffer: null,
        };
        //let ret = [{ cmd: (cmdH * 256 + cmdL), payload: payload, length: len }];
        return ret;
      } else {
        let pg = "";
        _packet.forEach((_pg) => {
          pg += `${_pg.toString(16).toUpperCase()} `;
        });
        console.log(pg);
        //let ret = [{ cmd: -1, payload: 'Payload invalid.', packet: _packet, length: 0 }];
        let ret = {
          status: 2,
          packet: [
            {
              cmd: -1,
              payload: "Payload invalid.",
              packet: _packet,
              length: 0,
            },
          ],
          remainingbuffer: _packet,
        };
        return ret;
      }
    }
  }
}

function sendPacket(_cmd, _payload) {
  // console.log(`sendPacket::::::::::::::::: ${(_cmd, _payload)}`);
  //Payload
  const buffer = Buffer.from(_payload, "utf-8");
  let len = buffer.length + 2;

  let buff = [];
  //Header
  let lenb = intToByteArray(len);
  //console.log(`len : ${len}-${lenb[0]} ${lenb[1]}`);

  buff.push(lenb.length);
  for (let i = lenb.length - 1; i >= 0; i--) {
    buff.push(lenb[i]);
    //console.log(`len : ${lenb[i].toString(16)}`);
  }
  if (lenb.length > 2 && lenb.length % 2 != 0) {
    buff[0] = lenb.length + 1;
    buff.push(0);
  }
  //Command
  let c = intToByteArray(_cmd);

  buff.push(c[0]);
  buff.push(c[1] ? c[1] : 0);

  buffer.forEach((bf) => {
    buff.push(bf);
  });

  /*let bb = '';
  buff.forEach(b => {
    bb += `{${b.toString(16).toUpperCase()}}`;
  });
  console.log(bb);*/

  // console.log(`send packet ::::::::::::::::::::${_cmd}, ${buff.length}`);
  return Buffer.from(buff);
}

function intToByteArray(int) {
  let byteArray = [];
  while (int > 0) {
    byteArray.push(int & 0xff); // Get the last 8 bits of the integer
    int = int >> 8; // Shift right by 8 bits
  }
  return byteArray.reverse(); // Reverse the array to get the correct order
}

function bufferToString(_buffer) {
  const decoder = new TextDecoder();
  let str = decoder.decode(_buffer);
  str = str.replace(/\0/g, ""); // Remove null bytes
  return str;
}
function generateRandomString() {
  const characters =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+[]{}|;:,.<>?";
  let result = "";
  for (let i = 0; i < 8; i++) {
    const randomIndex = Math.floor(Math.random() * characters.length);
    result += characters[randomIndex];
  }
  return result;
}

function convert(input) {
  // input format: YYYYMMDD HHmmss
  const year = input.slice(0, 4);
  const month = input.slice(4, 6);
  const day = input.slice(6, 8);
  const hour = input.slice(9, 11);
  const minute = input.slice(11, 13);
  const second = input.slice(13, 15);

  // Create Date object
  const date = new Date(
    `${year}-${month}-${day}T${hour}:${minute}:${second}.000Z`
  );

  // Format output with milliseconds
  const pad = (n, l = 2) => String(n).padStart(l, "0");
  const formatted = `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(
    date.getDate()
  )} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(
    date.getSeconds()
  )}.${pad(date.getMilliseconds(), 3)}`;

  return formatted;
}

function isDuplicateSend(history, payload) {
  return history.some(
    (h) =>
      h.MemberID == payload.MemberID &&
      h.DeviceID == payload.DeviceID &&
      h.Status == payload.Status
  );
}

module.exports = app;
