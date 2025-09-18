// websocket.js
const WebSocket = require('ws');
const EventEmitter = require('events');
//const pm2 = require('pm2');
const path = require('path');
const { command, loginStatus, onDeviceControlType, friendRight, deviceType, deviceControlType, connectionStatusType, disconnectTypeEnum } = require("../models/common");
const { admincommand } = require("../models/admincommon");
const { v4: uuidv4 } = require('uuid');

// const TCPServer = require('../server/tcpserver');
// const WebSocketManager = require('../server/websocketserver');

//websocket client list
let wsClient = [];

let logStack = []; //{date-time, type, cmd, message}


class WebSocketAdminManager {
    static eventEmitter = new EventEmitter();
    static wss = null;
    static socketClient = { ws: [], tcp: [] };


    static initialize(server) {
        if (this.wss) {
            throw new Error("WebSocket server is already initialized!");
        }

        this.wss = new WebSocket.Server({
            server: server,
            path: process.env.WS_ADMIN_PATH || "/admin",
        });

        this.wss.on('connection', (ws, req) => {
            const clientIP = req.socket.remoteAddress;
            const clientPort = req.socket.remotePort;

            console.log(`> [ADMIN] [${clientIP}:${clientPort}] Connected`);

            let csock = {
                id: uuidv4(),
                //buffer: new Uint16Array(),
                lastTimestamp: new Date().getTime(),
                socket: ws,
                info: {
                    id: 0,
                    name: '',
                    role: deviceType.Undefind,
                    friend: [], //{MemberID, Role}
                },
                islogin: false,
            };

            wsClient.push(csock);

            ws.on('message', (message) => {
                // Emit the message event
                //this.eventEmitter.emit('messageReceived', message);

                // Optionally broadcast the message to all clients
                //this.broadcast(message, ws);

                //console.log(`Received message: ${message}`);
                let payload;
                try {
                    payload = JSON.parse(message);

                }
                catch (error) {

                }

                if (payload != undefined) {// JSON Payload
                    console.log(`> [ADMIN] Received JSON: ${JSON.stringify(payload)}`);
                    if (payload.cmd) { // contain command
                        if (payload.param) { // contain parameter
                            const param = payload.param;
                            if (csock.islogin == false) {
                                if (payload.cmd == admincommand.Login) {
                                    if (param.Password == process.env.WS_ADMIN_PASSWORD) {
                                        console.log(`> [ADMIN] Credential pass.`);
                                        csock.islogin = true;
                                        let p = {
                                            cmd: command.Login,
                                            param: {
                                                Success: true
                                            }
                                        }
                                        ws.send(JSON.stringify(p));
                                    }
                                    else {
                                        console.log(`> [ADMIN] Credential failed.`);
                                    }
                                }
                            }
                            else {
                                if (payload.cmd == admincommand.Logout) {
                                    csock.islogin = false;
                                }
                                else if (payload.cmd == admincommand.GetClient) {
                                    console.log(JSON.stringify(WebSocketAdminManager.socketClient));
                                    const data = WebSocketAdminManager.socketClient;
                                    const response = {
                                        tcp: data.tcp.map((entry) => ({
                                            id: entry.id,
                                            lastTimestamp: entry.lastTimestamp,
                                            socketPeername: entry.socket?._peername,
                                            info: entry.info,
                                            islogin: entry.islogin,
                                        })),
                                        ws: data.ws.map((entry) => ({
                                            id: entry.id,
                                            lastTimestamp: entry.lastTimestamp,
                                            socketPeername: entry.socket?._socket?._peername,
                                            info: entry.info,
                                            islogin: entry.islogin,
                                        })),
                                    };
                                    let p = {
                                        cmd: admincommand.GetClient,
                                        param: {
                                            client: response
                                        }
                                    };
                                    ws.send(JSON.stringify(p));
                                }
                                else if (payload.cmd == admincommand.Log) {

                                }
                            }


                        }
                    }
                }
                else {// Plain text
                    console.log(`[ADMIN]\tReceived Plain text: ${message}`);
                }
            });

            ws.on('error', () => {
                console.log(`> [WS.Error] ${err}`);
            });
            ws.on('close', () => {
                console.log(`> [WS.Client] [${clientIP}:${clientPort}] Disconnected`);
            });
        });
    }

    static broadcast(message, sender) {
        if (!this.wss) {
            throw new Error("WebSocket server is not initialized!");
        }

        this.wss.clients.forEach((client) => {
            if (client !== sender && client.readyState === WebSocket.OPEN) {
                client.send(message);
            }
        });
    }

    static on(event, listener) {
        this.eventEmitter.on(event, listener);
    }

    static getClient(_tcpclient, _wsclient) {

    }
    static clientDisconnect(_kind, _uuid) {
        //console.log(_kind, _uuid);
        let p = {
            cmd: admincommand.ClientDisconnect,
            param: {
                type: _kind,
                id: _uuid
            }
        };
        //console.log(p);
        wsClient.forEach(c => {
            c.socket.send(JSON.stringify(p));
        });
    }
    static clientConnect(_kind, _info) {
        //console.log(_kind, _info);
        let p = {
            cmd: admincommand.ClientConnect,
            param: {
                type: _kind,
                info: _info
            }
        };
        //console.log(p);
        wsClient.forEach(c => {
            c.socket.send(JSON.stringify(p));
        });
    }
    static clientUpdateInfo(_kind, _info) {
        //console.log(_kind, _info);
        let p = {
            cmd: admincommand.ClientUpdateInfo,
            param: {
                type: _kind,
                info: _info
            }
        };
        //console.log(p);
        wsClient.forEach(c => {
            c.socket.send(JSON.stringify(p));
        });
    }
    static sendLog(_kind, _info) {
        //console.log(_kind, _info);
        let p = {
            cmd: admincommand.Log,
            param: {
                type: _kind,
                info: _info
            }
        };
        //console.log(p);
        wsClient.forEach(c => {
            c.socket.send(JSON.stringify(p));
        });
    }

    static sendToAll(message) {
        if (!this.wss) {
            throw new Error("WebSocket server is not initialized!");
        }

        this.wss.clients.forEach((client) => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(message);
            }
        });
    }
}

module.exports = WebSocketAdminManager;
//H:/Work/The Project/Solar cell/Application/Platform/IOTStandardServer