const httpServer = require('http').createServer();
const base64 = require('crypto-js/enc-base64');
const sha1 = require('crypto-js/sha1');
httpServer.listen(3000, ()=>console.log(`HTTP server started`))

function createFrame(message){
    let messageBuffer = Buffer.from(message, 'utf8');
    let messageBufferLength = messageBuffer.length;
    if(messageBufferLength<126){
        //Allocate 2 bytes for FIN, RSV1, RSV2, RSV3, OPCODE and payload length
        //Also, allocate some amount of bytes for the message
        const buffer = Buffer.alloc(2+messageBufferLength);
        //Write the first byte to set FIN, RSV1, RSV2, RSV3 and OPCODE
        buffer.writeUInt8(0b10000001, 0);
        //Write byte length of the message to the second byte
        buffer.writeUInt8(messageBufferLength, 1);
        //Write the message byte sequence to the other bytes 
        buffer.write(message, 2);
        return buffer;
    }else{
        throw new Error("Message length should be less than 128");
    }
}

function readFrame(data){

    let isFin = Boolean(data.readUInt8(0)>>7);

    if(isFin){
        let opcode = data.readUInt8(0)>>4;

        console.log('\n-------------------------------\n');
        console.log('Receiving a new message...');
        console.log(`Opcode: ${opcode}, is fin: ${isFin}`);

        let payloadLength = data.readUInt8(1)-128;
        let payloadLength126;
        let payloadLength127;
        let payloadInitSize = payloadLength;

        if(payloadLength===126){
            console.log("Payload length is equal to 126, attempt to use 2 bytes...");
            payloadLength126 = data.readUInt16BE(2);
        }

        if(payloadLength===127){
            console.log("Payload length is equal to 127, attempt to use 8 bytes...");
            payloadLength127 = data.readUInt32BE(2)+data.readUInt32BE(6);
        }

        payloadLength = payloadLength127||payloadLength126||payloadLength;

        console.log(`Payload length is calculated and its value is: ${payloadLength}`);

        if(payloadLength>0){

            let extendedPayloadIndex = payloadInitSize===126?2:payloadInitSize>=127?8:0;
            let resultBuffer = Buffer.alloc(payloadLength);
            let maskingKey = data.slice(2+extendedPayloadIndex, 6+extendedPayloadIndex);
            let payloadData = data.slice(6+extendedPayloadIndex, 6+payloadLength+extendedPayloadIndex)

            for(let i = 0; i<payloadData.length; i++){  
                resultBuffer.writeUInt8(payloadData.readUInt8(i)^maskingKey.readUInt8(i%4), i);
            }

            return resultBuffer.toString('utf8');

        }
    }else{
        return "Message is too large";
    }
}

httpServer.on('upgrade', (req, socket, head)=>{

    console.log('Websocket opening handshake...');
    console.log('Getting "Sec-WebSocket-Accept" header value...');
    let secWebSocketAcceptHeaderValue = req.rawHeaders[req.rawHeaders.findIndex((item)=>item==='Sec-WebSocket-Key')+1];
    console.log(`"Sec-WebSocket-Accept" header value is: ${secWebSocketAcceptHeaderValue}`);
    console.log('Appending "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" string to the "Sec-WebSocket-Accept" header value...');
    secWebSocketAcceptHeaderValue = secWebSocketAcceptHeaderValue + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
    console.log('Take SHA1 of "Sec-WebSocket-Accept" value...');
    secWebSocketAcceptHeaderValue = sha1(secWebSocketAcceptHeaderValue);
    console.log('Encode "Sec-WebSocket-Accept" value with base64...');
    secWebSocketAcceptHeaderValue = base64.stringify(secWebSocketAcceptHeaderValue);
    console.log('Switching HTTP protocol to the WS...');
    socket.write('HTTP/1.1 101 Web Socket Protocol Handshake\r\n' +
    'Sec-WebSocket-Accept: '+ secWebSocketAcceptHeaderValue +'\r\n' +
    'Upgrade: WebSocket\r\n' +
    'Connection: Upgrade\r\n' +
    '\r\n');

    socket.on('data', function(data){
        let framePayload = readFrame(data); 
        try{
            socket.write(createFrame(`The server received frame payload, it is equeal to: ${framePayload}`));
        }catch(e){
            console.log(e);
        }
        console.log(`The following message was received: ${framePayload}`);
    });

})