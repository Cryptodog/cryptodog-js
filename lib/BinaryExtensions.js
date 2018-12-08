const etc = require("etc-js");

const Op ={
  // Separates this extension from a regular plaintext Cryptodog message.
  BEX_MAGIC:          [4, 69, 255],

  NOT_VALID:          0,
  // Packet headers
  SET_COLOR:          1,
  PING:               2,
  PONG:               3,
  COMPOSING:          4,
  PAUSED:             5,
  FILE_ATTACHMENT:    6,
  TEXT_MESSAGE:       7,
  FLAG_ME_AS_BOT:     8,
  STATUS_ONLINE:      9,
  STATUS_AWAY:        10,
  // Moderation commands
  MOD_ELECTED:        11,
  // Removes all "borked" users, or users who are not responding to Multiparty messages
  CLEAR_DEAD_USERS:   12,
  SET_CONTROL_TABLE:  13,
  SET_LOCKDOWN_LEVEL: 14,
  WHITELIST_USER:     15,

  // WebRTC
  ICE_CANDIDATE:      30,
  RTC_OFFER:          31,
  RTC_ANSWER:         32,
  RTC_SIGNAL_CAPABILITY: 33,
  RTC_SIGNAL_DISABLED:   34
};

/**
 * @typedef   {Object}     Submessage
 * @property  {Number}     header
 * @property  {String}     [color]
 * @property  {Uint8Array} [fileEncryptionKey]
 * @property  {Uint8Array} [fileEncryptionNonce]
 * @property  {String}     [fileMime]
 * @property  {String}     [fileID]
 * @property  {String}     [status]
 * @property  {String}     [message]
 */
function Submessage(header) {
  this.header = header;
}

function toHex(c) {
  var h = c.toString(16);
  if (h.split("").length == 1) {
    h = "0" + h;
  }
  return h.toUpperCase();
}

function headerBytes(bytes) {
  if (bytes[0] == Op.BEX_MAGIC[0] &&
      bytes[1] == Op.BEX_MAGIC[1] && 
      bytes[2] == Op.BEX_MAGIC[2]) return true;
  return false;
}

/**
 * @param  {Uint8Array}   bytes
 * @return {Submessage[]}
 */
 function DecodeMessage(bytes) {
  var b        = new etc.Buffer(bytes);
  var packets  = [];
  var o = Op;

  var packetHeader = b.readBytes(3);

  if (headerBytes(packetHeader) == false) {
    return [];
  }

  var elements = b.readUint();
  if (elements > 8) return [];

  for (var i = 0; i < elements; i++) {
    var pack = {};
    pack.header = b.readUint();

    switch (pack.header) {
      // User color settings
      case o.SET_COLOR:

      // No need for escaping or validation, as any 3-byte array represents a color in hexadecimal
      var colorCodes = b.readBytes(3);
      pack.color     = "#" + etc.Encoding.encodeToHex(colorCodes);
      break;

      case o.PING:
      case o.PONG:
      pack.pingID = b.readUUID();
      break;
  
      case o.FILE_ATTACHMENT:
      pack.prefixSize        = b.readUint();
      pack.fileEncryptionKey = b.readBytes(32);
      pack.fileNonce         = b.readBytes(24);
      pack.fileMime          = b.readString();
      pack.fileID            = b.readUUID();
      break;
  
      case o.SET_STATUS:
      pack.status = b.readString();
      break;
  
      // Headers which have no body
      case o.COMPOSING:
      case o.PAUSED:
      case o.FLAG_ME_AS_BOT:
      break;
  
      case o.MESSAGE:
      pack.message = b.readString();
      break;

      // WebRTC metadata
      case o.RTC_OFFER:
      pack.target = b.readString();
      pack.offerSDP  = b.readString();
      break;

      case o.RTC_ANSWER:
      pack.target = b.readString();
      pack.answerSDP = b.readString();
      break;

      case o.ICE_CANDIDATE:
      pack.target = b.readString();
      pack.candidate = b.readString();
      pack.sdpMLineIndex = b.readUint();
      pack.sdpMid = b.readString();
      break;

      case o.SET_LOCKDOWN_LEVEL:
      pack.level = b.readUint();
      break;

      case o.SET_CONTROL_TABLE:
      pack.tableKey = b.readString();
      pack.table = new Array(b.readUint());
      for (var i = 0; i < pack.table.length; i++) {
        pack.table[i] = b.readString();
      }
      break;

      case o.WHITELIST_USER:
      case o.MOD_ELECTED:
      pack.target = b.readString();
      break;
    }

    packets.push(pack);
  }

  return packets;
}

/**
 * 
 * @param  {Submessage[]} array
 * @return {Uint8Array}
 */
function EncodeMessage(array) {
  var o = Op;
  var e = new etc.Buffer();
  e.writeBytes(o.BEX_MAGIC);
  e.writeUint(array.length);

  for (var i = 0; i < array.length; i++) {
    var packet = array[i];
    if (!packet.header) {
      e.writeUint(0);
      continue;
    }

    e.writeUint(packet.header);

    switch (packet.header) {
      case o.SET_COLOR:
      var bytes = etc.Encoding.decodeFromHex(packet.color.slice(1));
      if (bytes.length !== 3) {
        e.writeByte(0);
        e.writeByte(0);
        e.writeByte(0);
      } else {
        e.writeByte(bytes[0]);
        e.writeByte(bytes[1]);
        e.writeByte(bytes[2]);
      }
      break;

      case o.PING:
      case o.PONG:
      e.writeUUID(packet.pingID);
      break;

      case o.SET_STATUS:
      e.writeString(packet.status);
      break;

      case o.COMPOSING:
      case o.PAUSED:
      case o.FLAG_ME_AS_BOT:
      case o.STATUS_ONLINE:
      case o.STATUS_AWAY:
      case o.CLEAR_DEAD_USERS:
      break;

      case o.TEXT_MESSAGE:
      e.writeString(packet.messageType);
      e.writeString(packet.message);
      break;

      case o.RTC_OFFER:
      e.writeString(packet.target);
      e.writeString(packet.offerSDP);
      break;

      case o.RTC_ANSWER:
      e.writeString(packet.target);
      e.writeString(packet.answerSDP);
      break;

      case o.ICE_CANDIDATE:
      e.writeString(packet.target);
      e.writeString(packet.candidate);
      e.writeUint(packet.sdpMLineIndex);
      e.writeString(packet.sdpMid);
      break;

      case o.FILE_ATTACHMENT:
      e.writeUint(packet.prefixSize);
      e.writeBytes(packet.fileEncryptionKey);
      e.writeBytes(packet.fileNonce);
      e.writeString(packet.fileMime);
      e.writeUUID(packet.fileID);
      break;

      case o.SET_LOCKDOWN_LEVEL:
      e.writeUint(packet.level);
      break;

      case o.SET_CONTROL_TABLE:
      e.writeString(packet.tableKey);
      e.writeUint(packet.table.length);
      for (var i = 0; i < packet.table.length; i++) {
        e.writeString(packet.table[i]);
      }
      break;

      case o.WHITELIST_USER:
      case o.MOD_ELECTED:
      e.writeString(packet.target);
      break;
    }
  }

  return e.finish();
}


module.exports = {
  Decode:      DecodeMessage,
  Encode:      EncodeMessage, 
  Op:          Op,
  headerBytes: headerBytes,
};