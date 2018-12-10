const etc   = require("etc-js");
const crypt = etc.crypto;
const enc   = etc.Encoding;
const aesjs = require("aes-js");

const EventEmitter = require("events").EventEmitter;
const inherits     = require("inherits");
/**
 * @param  {Uint8Array} input
 * @return {Uint8Array}
 */
function sha512(input) {
  return crypt.nacl.hash(input);
}

function hmac(msg, key) {
  return crypt.hmac(msg, key);
}

function fixIV(b) {
  if (b.length < 12) return new Uint8Array(16);

  var by = new etc.Buffer();
  by.writeBytes(b.slice(0, 12));
  by.writeBytes([0, 0, 0, 0]);

  return by.finish();
}

function _strcmp(u8, _u8) {
  if (u8 == undefined || _u8 == undefined) {
    return 1;
  }
  if (u8.length !== _u8.length) return 1;

  for (var i = 0; i < u8.length; i++) {
    if (u8[i] !== _u8[i]) return 1;
  }

  return 0;
}

function streamAES(msg, key, iv) {
  var block = new aesjs.ModeOfOperation.ctr(key, iv);
  return block.encrypt(msg);
}

function messageTag(input) {
  var msg = input;

  for (var i = 0; i < 8; i++) {
    msg = sha512(msg);
  }

  return enc.encodeToBase64(msg);
}

inherits(Multiparty, EventEmitter);

function Multiparty(opts) {
  if (opts.privateKey) {
    // the user has supplied a private key in base 64
    this.privateKey = opts.privateKey;
  } else {
    this.privateKey = crypt.nacl.randomBytes(32);
  }

  this.publicKey = crypt.nacl.scalarMult.base(this.privateKey);
  this.me        = opts.me;
  this.peers     = {};
  this.usedIVs   = [];

  EventEmitter.call(this);
}

Multiparty.streamAES = streamAES;
Multiparty.hmac = hmac;

Multiparty.prototype._out = function(d) {
  this.emit("io", JSON.stringify(d));
}

Multiparty.prototype.sendPublicKey = function(nick) {
  this._out({
    type: "public_key",
    text: enc.encodeToBase64(this.publicKey)
  });

  if (!nick) return;

  if (!this.peers[nick]) this.peers[nick] = {};

  this.peers[nick].sentKey = true;

  if (this.peers[nick].publicKey && !this.peers[nick].established) {
    this.emit("establish", nick);
  }
}

Multiparty.prototype.genSharedSecret = function(nick) {
  var secret = new Uint8Array(32);
  crypt.nacl.lowlevel.crypto_scalarmult(secret, this.privateKey, this.peers[nick].publicKey)
  var secretHash = sha512(secret);
  return {
    msg:  secretHash.slice(0, 32),
    hmac: secretHash.slice(32, 64)
  };
}

Multiparty.prototype.destroyPeer = function(nick) {
  delete this.peers[nick];
}

Multiparty.prototype.init = function() {
  this.requestPublicKey();
  this.sendPublicKey();
}

Multiparty.prototype.requestPublicKey = function(nick) {
  this._out({
    type: "public_key_request",
    text: nick || ""
  });
}

Multiparty.prototype.peerExclusion = function(nick) {
  return Object.keys(this.peers).filter(v => v !== nick);
}

Multiparty.prototype.sendExclusiveMessage = function(nick, msg) {
  this.sendMessage(msg, this.peerExclusion(nick));
}

Multiparty.prototype.sendTriggeredMessage = function(nickGex, msg) {
  var bl = Object.keys(this.peers).filter(v => nickGex.test(v) == false);
  this.sendMessage(msg, bl);
}

Multiparty.prototype.sendMessage = function(msg, blacklist) {
  blacklist = blacklist || [];

  var tagg = crypt.nacl.randomBytes(64);
  var msg = new etc.Buffer(msg);
  msg.writeBytes(tagg);

  var mesg = msg.finish();
  
  var encrypted = {
    type: "message",
    text: {}
  };

  var buds = Object.keys(this.peers);

  var sortedRecipients = [];

  for (var i = 0; i < buds.length; i++) {
    var k = buds[i];
    if (this.peers[k].publicKey && blacklist.includes(k) == false) {
      sortedRecipients.push(k);
    }
  }

  sortedRecipients.sort();

  var bhmac = new etc.Buffer();

  for (var i = 0; i < sortedRecipients.length; i++) {
    var v = sortedRecipients[i];
    if (!this.peers[v]) continue;
    if (!this.peers[v].mpSecretKey) continue;

    var iv, eiv;
    
    for (; ;) {
      iv = fixIV(crypt.nacl.randomBytes(12));
      eiv = enc.encodeToBase64(iv);
  
      if (this.usedIVs.includes(eiv)) {
        continue;
      } else {
        break
      }
    }

    this.usedIVs.push(eiv);

    var aesData = streamAES(mesg, this.peers[v].mpSecretKey.msg, iv);
    encrypted.text[v] = {
      message: enc.encodeToBase64(aesData),
      iv:      eiv
    };

    bhmac.writeBytes(aesData);
    bhmac.writeBytes(iv);
  }

  var tgg = bhmac.finish()

  var tag = new etc.Buffer(mesg);
  for (var i = 0; i < sortedRecipients.length; i++) {
    var v = sortedRecipients[i];
    var he = hmac(tgg, this.peers[v].mpSecretKey.hmac);
    encrypted.text[v].hmac = enc.encodeToBase64(he);
    tag.writeBytes(he);
  }

  encrypted.tag = messageTag(tag.finish());

  this._out(encrypted);
}

Multiparty.prototype.fingerprint = function (nick) {
  if (!this.peers[nick]) {
    return;
  }

  return etc.Encoding.encodeToHex(sha512(this.peers[nick].publicKey)).toUpperCase();
}

Multiparty.prototype.receiveMessage = function(nick, msg) {
  var obj = {};
  try { obj = JSON.parse(msg); } catch(e) { return "could not parse JSON: " + e; };
  if (nick == this.me) return null;

  switch (obj.type) {
    case "public_key":
    var keyData = enc.decodeFromBase64(obj.text);
    if (keyData.length != 32) return "invalid key length";

    if (!this.peers[nick]) {
      this.peers[nick] = {};
    } else {
      if (_strcmp(this.peers[nick].publicKey, keyData) !== 0) {
        this.emit("keychange", nick);
      }
    }

    this.peers[nick].publicKey   = keyData;
    this.peers[nick].mpSecretKey = this.genSharedSecret(nick); 

    if (!this.peers[nick].established && this.peers.sentKey) {
      this.peers[nick].established = true;
      this.emit("establish", nick);
    }
    return null;
    break;

    case "public_key_request":
    if (obj.text == this.me) {
      this.sendPublicKey(nick);
    } else {
      if (obj.text == null || obj.text == "") {
        this.sendPublicKey(nick);
      }
    }

    return null;
    break;

    case "message":
    if (!obj.text[this.me]) return "no text object";
    if (!this.peers[nick])  return "peer not found";

    if (!this.peers[nick].publicKey) {
      this.requestPublicKey(nick)
      return null;
    }

    var emission = {
      missingRecipients: []
    };

    var peerNames = Object.keys(this.peers);

    for (var i = 0; i < peerNames.length; i++) {
      function undef(i) {
        return i == "" || typeof i == "undefined";
      } 

      if (
         undef(obj.text[peerNames[i]])
         || undef(obj.text[peerNames[i]].message)
         || undef(obj.text[peerNames[i]].hmac)
         || undef(obj.text[peerNames[i]].iv)) {
        emission.missingRecipients.push(peerNames[i]);
      }
    }

    var sortedRecipients = Object.keys(obj.text).sort();
    var bhmac = new etc.Buffer();

    for (var k = 0; k < sortedRecipients.length; k++) {
      var v = sortedRecipients[k];
      if (emission.missingRecipients.includes(v) == false) {
        var msgb = enc.decodeFromBase64(obj.text[v].message);
        var ivb = enc.decodeFromBase64(obj.text[v].iv);
        bhmac.writeBytes(msgb);
        bhmac.writeBytes(ivb);
      }
    }

    var secretMAC = this.peers[nick].mpSecretKey.hmac;
    var pHMAC     = hmac(bhmac.finish(), secretMAC);
    var rHMAC     = enc.decodeFromBase64(obj.text[this.me].hmac)

    if (_strcmp(pHMAC, rHMAC) !== 0) {
      return "hmac does not match";
    } 

    if (this.usedIVs.includes(obj.text[this.me].iv)) {
      return "reuse of IV";
    }

    this.usedIVs.push(obj.text[this.me].iv);

    var ivbytes = fixIV(enc.decodeFromBase64(obj.text[this.me].iv));
    var mdata = enc.decodeFromBase64(obj.text[this.me].message);
    var plaintext = streamAES(mdata, this.peers[nick].mpSecretKey.msg, ivbytes);
    var mtag = new etc.Buffer();
    mtag.writeBytes(plaintext);

    for (var i = 0; i < sortedRecipients.length; i++) {
      var h = enc.decodeFromBase64(obj.text[sortedRecipients[i]].hmac);
      mtag.writeBytes(h);
    }

    var pTag = messageTag(mtag.finish()); 
    if (pTag !== obj.tag) return "tag mismatch";

    if (plaintext.length < 64) return "plaintext too small";

    var text = plaintext.slice(0, plaintext.length-64);

    emission.from = nick;
    emission.body = text;

    this.emit("message", emission);
    return null;
    break;
  }
} 

module.exports = Multiparty;