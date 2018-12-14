const etc          = require("etc-js");
const inherits     = require("inherits");
const EventEmitter = require("events").EventEmitter;
const sz           = require("stanza.io");
const Multiparty   = require("./Multiparty");
const MapStore     = require("./Storage/MapStore");
const OTR          = require("otr").OTR;
const DSA          = require("otr").DSA;
const BEX          = require("./BinaryExtensions");
const Op           = BEX.Op;
const validateUTF8 = etc.Encoding.validateUTF8;

inherits(Conn, EventEmitter);

function Conn(opts) {
  opts = opts || {};
  this.endpoint    = opts.endpoint   || "wss://crypto.dog/websocket";
  this.serverJID   = opts.serverJID  || "crypto.dog";
  this.confJID     = opts.confJID    || "conference.crypto.dog";
  this.bexServer   = opts.bexServer  || "https://bex.pg.ikrypto.club/";

  this.password   = opts.password;
  this.debug      = opts.debug;
  if (opts.useBex !== false) {
    this.useBex = true;
  } else {
    this.useBex = false
  }

  this.colors = {};

  this._joinCb = {};
  this._ensureOtr = {};

  this.store = opts.store || new MapStore();

  this.groupConversations = {};
  this.privateConversations = {};
  this.roomNames = {};

  if (this.useBex === true) {
    this.on("gm-binary",      this._bexGroup.bind(this));
    this.on("dm-binary",      this._bexPrivate.bind(this));
    this.on("room-connected", this._bexGroupInit.bind(this));
  }

  EventEmitter.call(this);
}

Conn.prototype.getBuddies = function(r) {
  if (!this.groupConversations[r]) {
    return [];
  }

  return Object.keys(this.groupConversations[r].peers).sort();
}

Conn.prototype.getAuthState = function(r, nick) {
  if (!this.authState[r]) {
    return 0;
  }  

  return this.authState[r][nick].state;
}

/**
 * @return {RTCConfiguraton}
 */
Conn.prototype.createRTCConfiguration = function() {
  var turnu = new etc.URL(this.bexServer);
  var turn = "turn:" + turnu.host + ":3478";
  return {
    "iceTransportPolicy": "relay",
    "iceServers": [
      { "url":        turn,
        "username":   "cryptodog",
        "credential": "preventing-ip-leakage"
      }
    ]
  }
}

/**
 * @param {etc.UUID} id
 */
Conn.prototype.constructDownloadURL = function(id) {
  return 
    new etc.URL(this.bexServer)
    .subPath("/files/" + id.toString())
    .toString();
}

/**
* Encrypt, upload, and send file to the group conversation
* 
* @param  {String}     room
* @param  {String}     mimeType 
* @param  {Uint8Array} data
* @param  {Function}   progress
* @return {Promise<null>}
*/
Conn.prototype.sendGroupAttachment = function (room, mimeType, plaintext, progress) {
  var $this = this;
  var start = $this.mpFingerprint(room, user);

  return $this.createAttachment(mimeType, plaintext, progress)
  .then(function(submessage) {
    if (start === end) {
      $this.sendBexGroup(room, [submessage]);
    }
  });
}

/*
* Encrypt, upload, and send file to a user in PM.
* 
* @param  {String}     room
* @param  {String}     mimeType 
* @param  {Uint8Array} data
* @param  {Function}   progress
* @return {Promise<null>}
*/
Conn.prototype.sendPrivateAttachment = function (room, user, mimeType, plaintext, progress) {
  var $this = this;

  return $this.createAttachment(mimeType, plaintext, progress)
  .then(function(submessage) {
    $this.sendBexPrivate(room, user, [submessage]);
  });
}

Conn.prototype.mpFingerprint = function (room, user) {
  if (!this.groupConversations[room]) {
    return;
  }

  return this.groupConversations[room].fingerprint(user);
}

Conn.prototype.otrFingerprint = function (room, user) {
  if (!this.privateConversations[room]) {
    return;
  }

  var o = this.privateConversations[room][user];
  if (!o) {
    return;
  }

  if (o.their_priv_pk === null) {
    return;
  }

  return o.their_priv_pk.fingerprint().toUpperCase();
}


/**
 * Encrypt and upload a file.
 * 
 * @param  {String}     mimeType 
 * @param  {Uint8Array} data
 * @param  {Function}   progress
 * @return {Promise<Object>}
 */
Conn.prototype.createAttachment = function (mimeType, plaintext, progress) {
  var prefixLen = etc.ChooseRandom(2000, 14000);

  var envelope = new etc.Buffer();
  envelope.writeBytes(etc.crypto.nacl.randomBytes(prefixLen));
  envelope.writeBytes(plaintext);

  var nonce = etc.crypto.nacl.randomBytes(24);
  var key = etc.crypto.nacl.randomBytes(32);

  var ciphertext = etc.crypto.nacl.secretbox(envelope.finish(), nonce, key);

  var url = new etc.URL(this.bexServer);
  var postURL = url.subPath("/upload")
                .setQ("cl", ciphertext.length.toString())
                .toString();

  return new Promise(function(y, n) {
    new etc.Req({
      method:  "POST",
      url:     postURL,
      payload: ciphertext,
      onUploadProgress: function (prog) {
        if (progress) {
          progress(prog);
        }
      }
    })
    .do()
    .then(function(resp) {
      switch (resp.status) {
        case 200:
        var obj = {
          header:              BEX.Op.FILE_ATTACHMENT,
          fileID:              new etc.Buffer(resp.data).readUUID(),
          prefixSize:          prefixLen,
          fileMime:            mimeType,
          fileEncryptionKey:   key,
          fileEncryptionNonce: nonce
        };

        y(obj);
        break;

        case 0, 502:
        n("no connection to server");
        break;

        case 400, 409:
        n("bad request");
        break;

        case 429:
        n("too many requests");
        break;

        case 500:
        n("server ran out of space");
        break;
      }
    });
  });
}

/**
 * 
 * @param {Object}   evt 
 * @param {Function} progress 
 */
Conn.prototype.retrieveAttachment = function(evt, progress) {
  var $this = this;

  return new Promise(function(y, n) {
    new etc.Req({
      method:             "GET",
      url:                $this.constructDownloadURL(evt.fileID),
      onDownloadProgress: function(prog) {
        if (progress) {
          progress(prog);
        }
      }
    })
    .do()
    .then(function (data) {
      if (data.status !== 200) {
        var msgp = {
          409: "this client has sent a malformed request",
          429: "you have sent too many requests",
          500: "the server appears to have run out of space",
          404: "this file was deleted"
        }

        var msg = msgp[data.status];
        if (!msg) {
          msg = "unknown error: " + data.status.toString();
        }
 
        n(msg);
        return;
      }

      var data = etc.nacl.secretbox.open(data.data, evt.fileEncryptionNonce, evt.fileEncryptionKey);
      if (data === null) {
        n("could not decrypt file");
        return;
      }

      data = data.slice(evt.prefixSize);

      y({
        fileData: data,
        fileMime: evt.fileMime
      });
    });
  });
}

Conn.prototype._bexGroupInit = function(evt) {
  var $this = this;

  function sendIntro(color) {
    var int = [
      { header: this.status === "online" ? Op.STATUS_ONLINE : Op.STATUS_AWAY },
      { header: Op.SET_COLOR, color: color }
    ];

    if ($this.rtcEnabled === true) {
      int.push({ header: Op.RTC_SIGNAL_CAPABILITY });
    }

    $this.sendBexGroup(evt.room, int);
  }

  $this.store.getItem("color")
  .then(function (co) {
    if (co) {
      sendIntro($this.color);
    } else {
      sendIntro("#000000");
    }
  });
}

// Changes your nick color in one room
Conn.prototype.changeRoomColor = function (r, color) {
  var $this = this;
  if (/^#[a-f0-9]{6}$/i.test(color) == false) {
    throw new Error(color + "is not valid");
  }

  $this.colors[r] = color;

  $this.sendBexGroup(r, [{
    header: Op.SET_COLOR,
    color:  $this.colors[r]
  }]);
}

// Changes your nick color globally
Conn.prototype.changeColor = function (color) {
  var $this = this;
  Object.keys($this.groupConversations).forEach((gc) => {
    $this.changeRoomColor(gc, color);
  });

  $this.store.setItem("color", color);
}

/**
 * @param {String} r 
 * @param {Array}  pkt 
 */
Conn.prototype.sendBexGroup = function(r, pkt) {
  if (!this.useBex) {
    return;
  }
  var data = BEX.Encode(pkt);
  console.log("sending", data);
  this.groupConversations[r].sendMessage(data);
}

/**
* @param {String} r 
* @param {String} user
* @param {Array}  pkt 
*/
Conn.prototype.sendBexPrivate = function(r, user, pkt) {
  if (!this.useBex) {
    return;
  }
  var data = BEX.Encode(pkt);
  this.privateConversations[r][user].sendMsg(etc.Encoding.encodeToBase64(data));
}

Conn.prototype._bexGroup = function(evt) {
  var $this = this;
  var packets = BEX.Decode(evt.body);

  packets.map(function(packet) {
    switch (packet.header) {
      case Op.NOT_VALID:
      break;
  
      case Op.SET_COLOR:
      $this.emit("color-modify", {
        from:  evt.from,
        room:  evt.room,
        color: packet.color
      });
      break;

      case Op.COMPOSING:
      $this.emit("gm-composing", {
        from:              evt.from,
        room:              evt.room
      });
      break;

      case Op.PAUSED:
      $this.emit("gm-paused", {
        from: evt.from,
        room: evt.room
      });
      break;
  
      case Op.FILE_ATTACHMENT:
      $this.emit("gm-file", {
        from:              evt.from,
        room:              evt.room,
        fileEncryptionKey: packet.fileEncryptionKey,
        fileMime:          packet.fileMime,
        fileID:            packet.fileID,
      });
      break;
    }
  });
}

Conn.prototype._bexPrivate = function(evt) {
  var $this = this;
  var packets = BEX.Decode(evt.body);

  packets.map(function(packet) {
    switch (packet.header) {
      case Op.COMPOSING:
      $this.emit("dm-composing", {
        from:              evt.from,
        room:              evt.room
      });
      break;

      case Op.PAUSED:
      $this.emit("dm-paused", {
        from: evt.from,
        room: evt.room
      });
      break;
  
      case Op.FILE_ATTACHMENT:
      $this.emit("dm-file", {
        from:              evt.from,
        room:              evt.room,
        fileEncryptionKey: packet.fileEncryptionKey,
        fileMime:          packet.fileMime,
        fileID:            packet.fileID,
      });
      break;
    }
  });
}

Conn.prototype.ensureOtrFingerprint = function(r, nick) {
  var $this = this;

  return new Promise(function(y, n) {
    var resolved = false;

    function resolve(o) { 
      resolved = true;
      delete $this._ensureOtr[r + "-" + nick];
      y(o);
    }

    if (!$this.privateConversations[r]) {
      n("no group conversation");
      return;
    }

    if (!$this.privateConversations[r][nick]) {
      $this._ensureOtr[r + "-" + nick] = function() {
        resolve($this.otrFingerprint(r, nick));
      }
    } else {
      y($this.otrFingerprint(r, nick));
    }

    setTimeout(function() {
      if (!resolved) {
        n("timeout");
        delete $this._ensureOtr[r + "-" + nick];
      }
    }, 10000);
  });
}

Conn.prototype._roomJID = function(roomString) {
  return [roomString, "@", this.confJID].join("");
}

Conn.prototype.joinRoom = function(r, name) {
  var $this = this;

  if (!$this.privateConversations[r]) $this.privateConversations[r] = [];

  $this.store.getItem("rooms").then(function(rooms) {
    if (!rooms) {
      rooms = [];
    }

    var inc = false

    rooms.map(function(room) {
      if (inc === false) {
        inc = room.conversation === r;
      }
    });

    if (!inc) {
      rooms.push({
        conversation: r,
        nickname:     name
      });
      $this.store.setItem("rooms", rooms);
    }

    $this._stanza.joinRoom(
      $this._roomJID(r),
      name,
      { status: "online", joinMuc: { password: $this.password }});
    
    $this._joinCb[r] = function() {
      var gc = new Multiparty({
        me:         name,
        privateKey: $this.mpSecretKey
      });

      gc.on("io", function(d) {
        $this._sendGM(r, d);
      })

      gc.on("newkey", function(evt) {
        function join() {
          $this.emit("join", {
            nickname: evt.peer,
            room:     r
          });
        }

        if ($this.authState[r]) {
          if ($this.authState[r][evt.peer]) {
            if ($this.authState[r][evt.peer].mp !== evt.fingerprint) {
              $this.updateAuthenticationState(r, evt.peer, 0);
            } else {
              $this.ensureOtrFingerprint()
              .then(function(otr) {
                if (otr !== $this.authState[r][evt.peer].otr) {
                  join();
                  $this.updateAuthenticationState(r, evt.peer, 0);
                } else {
                  join();
                }
              })
              .catch(function() {
                join();
                $this.updateAuthenticationState(r, evt.peer, 0);
              })
            }
          } else {
            join();
          }
        } else {
          join();
        }
      });

      gc.on("keychange", function(d) {
        $this.emit("multiparty-key-change", d);
        $this.updateAuthenticationState(r, d, 0);
      }); 

      gc.on("message", function(d) {
        if (validateUTF8(d.body)) {
          $this.emit("gm", {
            body: etc.Encoding.encodeToUTF8(d.body),
            room: r,
            from: d.from
          });
        } else {
          $this.emit("gm-binary", {
            room: r,
            from: d.from,
            body: d.body
          });
        }
      })

      gc.init();

      $this.groupConversations[r] = gc;

      $this.roomNames[r] = name;
      
      $this.emit("room-connected", {
        room:     r,
        nickname: name
      });

      delete $this._joinCb[r];
    }
  });
}

Conn.prototype.updateAuthenticationState = function(r, nick, state) {
  var $this = this;

  if (!$this.authState[r]) {
    $this.authState[r] = {};
  }

  $this.ensureOtrFingerprint(r, nick)
  .then(function(otrf) {
    $this.authState[r][nick] = {
      otr:   otrf,
      mp:    $this.mpFingerprint(r, nick),
      state: state
    }
      
    $this.emit("authchange", {
      room:     r,
      nickname: nick,
      state:    state
    });

    $this.store.setItem("authState", this.authState);
  })
  .catch(function(err) {
    delete $this.authState[r][nick];
    this.emit("authchange", {
      room:     r,
      nickname: nick,
      state:    0
    });
  })
}


/**
 * Sends a binary string to a Multiparty group conversation
 * 
 * @param {String}     r 
 * @param {Uint8Array} msg 
 */
Conn.prototype.sendGroupBuffer = function(r, msg) {
  var gc = this.groupConversations[r];
  if (gc) {
    gc.sendMessage(msg);
  }
}

/**
 * Sends a text to a Multiparty group conversation
 * 
 * @param {String} r 
 * @param {String} msg 
 */
Conn.prototype.sendGroupMessage = function(r, msg) {
  if (validateUTF8(toBytes(msg)) == false) {
    console.log("Attempted to send invalid text");
    return;
  }
  this.sendGroupBuffer(r, etc.Encoding.decodeFromUTF8(msg));
}

/**
 * Sends a direct message to a user
 * 
 * @param {String}     r 
 * @param {String}     nick 
 * @param {String}     msg 
 */
Conn.prototype.sendPrivateMessage = function (r, nick, msg) {
  if (!this.privateConversations[r]) {
    console.log("No room object", r);
    return;
  }

  if (!this.privateConversations[r][nick]) {
    this.setupOTR(r, nick);
  }

  var o = this.privateConversations[r][nick]
  o.sendMsg(msg);    
}

Conn.prototype.sendPrivateBuffer = function (r, nick, msg) {
  this.sendPrivateMessage(r, nick, etc.Encoding.encodeToBase64(msg))
}

Conn.prototype.sendComposing = function(r) {
  this._stanza.sendMessage({
    type:      "groupchat",
    to:        this._roomJID(r),
    chatState: "composing"
  });
} 

Conn.prototype.sendPaused = function(r) {
  this._stanza.sendMessage({
    type:      "groupchat",
    to:        this._roomJID(r),
    chatState: "paused"
  });
} 

Conn.prototype._sendGM = function(r, msg) {
  var $this = this;
  $this._stanza.sendMessage({
    to:   $this._roomJID(r),
    body: msg,
    type: "groupchat"
  });
}

Conn.prototype.setupOTR = function(room, from) {
  var $this = this;

  var o = new OTR({
    priv: $this.otrKey
  });

  o.REQUIRE_ENCRYPTION = true;

  o.on("ui", function(msg, encrypted, meta) {
    if (msg.startsWith("BEX/")) {
      msg = etc.Encoding.decodeFromBase64(msg);
      if (BEX.headerBytes(msg)) { 
        $this.emit("dm-binary", {
          room: room,
          from: from,
          body: msg
        });
      }
    } else {
      $this.emit("dm", {
        room: room,
        from: from,
        body: msg
      });
    }
  });

  o.on("status", function(state) {
    if (state === OTR.CONST.STATUS_AKE_SUCCESS) {
      o._cdInit = true;
      $this.emit("otr", {
        from: from,
        room: room
      });
      if ($this._ensureOtr[room + "-" + from]) {
        $this._ensureOtr[room + "-" + from]();
      }
    }

    if (state === OTR.CONST.STATUS_END_OTR) {
      $this.emit("otr-end", {
        from: from,
        room: room
      });
    }
  });

  o.on("io", function(msg) {
    var to = [room, "@", $this.confJID, "/", from].join("");
    console.log("sending to", to, msg);
    $this._stanza.sendMessage({
      type: "chat",
      to:   to,
      body: msg
    });
  });

  $this.privateConversations[room][from] = o;
}

Conn.prototype._buddyTo = function(room, buddy) {
  var $this = this;
  return [room, "@", $this.confJID, "/", buddy].join("")
}

Conn.prototype._genSID = function(i) {
  return new etc.UUID().toString();
}

Conn.prototype.connect = function() {
  var $this = this;

  $this.store.getItem("authState")
  .then(function(ats) {
    $this.authState = ats || {};
    return $this.store.getItem("keys");
  })
  .then(function(k) {
    if (k) {
      console.log("Key data", k);
      $this.mpSecretKey = etc.Encoding.decodeFromBase64(k.mp);
      $this.otrKey      = DSA.parsePrivate(k.dsa);
      console.log("loaded keys");
      loaded();
    } else {
      $this.mpSecretKey = etc.crypto.nacl.randomBytes(32);
      $this.otrKey = new DSA();
      $this.store.setItem("keys", {
        dsa: $this.otrKey.packPrivate(),
        mp:  etc.Encoding.encodeToBase64($this.mpSecretKey)
      }).then(function() {
        console.log("Set keys");
        loaded();
      })
    }
  });

  function loaded() {
    $this._stanza = sz.createClient({
      jid:       $this.serverJID,
      transport: "websocket",
      wsURL:     $this.endpoint,
      sasl:      ["anonymous"]
    });

    $this._stanza.on("session:started", function() {
      $this.emit("connected", {});

      $this.store.getItem("rooms")
      .then(function(rooms) {
        if (!rooms) {
          rooms = [];
          $this.store.setItem("rooms", rooms);
        }
        rooms.forEach(function(roomString) {
          $this.joinRoom(roomString);
        });
      });
    });

    if ($this.debug) {
      $this._stanza.on("raw:outgoing", function(data) {
        console.log("--> ", data);
      });

      $this._stanza.on("raw:incoming", function(data) {
        console.log("<-- ", data);
      });
    }

    $this._stanza.on("muc:leave", function(data) {
      var from = data.from.resource;
      var room = data.from.unescapedLocal
      $this.emit("leave", {
        from: from,
        room: room
      });
      if ($this.privateConversations[room]) {
        if ($this.privateConversations[room][from]) {
          delete $this.privateConversations[room][from];
        }
      }
      if ($this.groupConversations[room]) {
        $this.groupConversations[room].destroyUser(from);
      }
    })

    $this._stanza.on("muc:join", function(data) {
      if ($this._joinCb[data.from.local]) {
        $this._joinCb[data.from.local]();
        return;
      }
    });
    
    $this._stanza.on("chat", function(data) {
      var from = data.from.resource;
      var room = data.from.unescapedLocal;

      if (!$this.privateConversations[room]) {
        $this.privateConversations[room] = {};
      }

      if (!$this.privateConversations[room][from]) {
        $this.setupOTR(room, from);
      }

      if (data.body) {
        $this.privateConversations[room][from].receiveMsg(data.body);
      }
    });

    $this._stanza.on("groupchat", function(data) {
      var from = data.from.resource;
      var room = data.from.unescapedLocal;

      // Do not process messages from me.
      if (from === $this.roomNames[room]) {
        return;
      }

      var gc = $this.groupConversations[room];

      if (data.id == "composing") {
        $this.emit("composing", {
          room: room,
          from: from
        });
        return;
      }

      if (data.id == "paused") {
        $this.emit("paused", {
          room: room,
          from: from
        });
        return;
      }

      if (gc) {
        var err
        err = gc.receiveMessage(from, data.body);
        if (err !== null) {
          console.warn(err);
        }
      }
    });

    $this._stanza.on("muc:error", function(data) {
      if (data.error.code == "409") {
        $this.destroyRoom(data.from.unescapedLocal);

        $this.emit("nickname-in-use", {
          nickname: data.from.resource,
          room:     data.from.unescapedLocal
        });
        return
      }
    })

    $this._stanza.connect();
  }
}

Conn.prototype.destroyRoom = function(room) {
  var $this = this;
  delete $this.privateConversations[room];
  delete $this.groupConversations[room];
}

Conn.prototype.disconnect = function(cb) {
  var $this = this;
  $this.store.getItem("rooms").then(function(rooms) {
    if (!rooms) {
      rooms = [];
    }

    var wg = rooms.length;

    if (wg == 0) {
      $this._stanza.disconnect();
      setTimeout(function() {
        if (cb) {
          cb();
        }
      }, 200);
      return;
    }

    rooms.forEach(function(r) {
      $this._stanza.leaveRoom(r + "@" + $this.confJID);
      done();
    });
    function done() {
      wg --;
      if (wg == 0) {
        $this._stanza.disconnect();
        setTimeout(function() {
          cb();
        }, 200);
      }
    }
  });
}

Conn.prototype.destroy = function() {
  this.store.clear();
  this.disconnect();
}

module.exports = Conn;

function toBytes(string) {
  return etc.Encoding.decodeFromUTF8(string);
}