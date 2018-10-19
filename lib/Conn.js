const etc          = require("etc-js");
const inherits     = require("inherits");
const EventEmitter = require("events").EventEmitter;
const sz           = require("stanza.io");
const Multiparty   = require("./Multiparty");
const MapStore     = require("./Storage/MapStore");

inherits(Conn, EventEmitter);

function Conn(opts) {
  opts = opts || {};
  this.nickname   = opts.nickname;
  this.endpoint   = opts.endpoint   || "wss://crypto.dog/websocket";
  this.serverJID  = opts.serverJID  || "crypto.dog";
  this.confJID    = opts.confJID    || "conference.crypto.dog";
  this.password   = opts.password;
  this.groupConversations = {};
  this._joinCb = {};
  this.store = opts.store || new MapStore();

  EventEmitter.call(this);
}

Conn.prototype._roomJID = function(roomString) {
  return [roomString, "@", this.confJID].join("");
}

Conn.prototype.joinRoom = function(r) {
  var $this = this;

  $this.store.getItem("rooms", function(rooms) {
    if (!rooms) {
      rooms = [];
    }

    if (!rooms.includes(r)) {
      rooms.push(rooms);
      rooms.sort();
      $this.store.setItem("rooms", rooms);
    }

    $this._stanza.joinRoom(
      $this._roomJID(r),
      $this.nickname,
      { status: "online", joinMuc: { password: $this.password }});
    
    $this._joinCb[r] = function() {
      var gc = new Multiparty({
        me:       $this.nickname,
        onOutput: function(d) {
          $this._sendGM(r, d);
        }
      });

      gc.on("keychange", function(d) {
        $this.emit("mpKeyChange", d);
      }); 

      gc.on("message", function(d) {
        $this.emit("groupMessage", {
          body: d.body,
          room: r
        });
      })

      gc.init();

      $this.groupConversations[r] = gc;
  
      $this.emit("roomConnected", {
        room: r
      });

      delete $this._joinCb[r];
    }
  });
}

Conn.prototype.sendGroupMessage = function(r, msg) {
  var gc = this.groupConversations[r];
  if (gc) {
    gc.sendMessage(msg);
  } else {
    console.log("no group message", r, msg)
  }
}

Conn.prototype._sendGM = function(r, msg) {
  var $this = this;
  $this._stanza.sendMessage({
    to:   $this._roomJID(r),
    body: msg,
    type: "groupchat"
  });
}

Conn.prototype.connect = function() {
  var $this = this;

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

  $this._stanza.on("muc:leave", function(data) {
    $this.emit("leave", {
      from: data.from.resource,
      room: data.from.unescapedLocal
    });
  })

  $this._stanza.on("muc:join", function(data) {
    console.log("join", data);
    if ($this._joinCb[data.from.local]) {
      $this._joinCb[data.from.local]()
      return;
    }
  });

  $this._stanza.on("groupchat", function(data) {
    var from = data.from.resource;
    var room = data.from.unescapedLocal;

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
        console.log(err);
      } else {
        console.log("Message from", from, "returned null");
      }
    }
  });

  $this._stanza.on("muc:error", function(data) {
    if (data.error.code == "409") {
      $this.emit("nicknameInUse", {
        nickname: data.from.resource,
        room:     data.from.unescapedLocal
      });
      return
    }
  })

  $this._stanza.connect();
}

Conn.prototype.disconnect = function() {
  var $this = this;
  $this.store.getItem("rooms", function(rooms) {
    if (!rooms) {
      rooms = [];
    }
    rooms.forEach(function(r) {
      $this._stanza.leaveRoom(r + "@" + $this.confJID);
    });
    $this._stanza.disconnect();
  });
}

Conn.prototype.destroy = function() {
  this.store.clear();
  this.disconnect();
}

module.exports = Conn;
