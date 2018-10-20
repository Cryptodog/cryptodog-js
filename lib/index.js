var ctor = require("./Conn");
ctor.ReactNativeStore = require("./Storage/ReactNativeStore");
ctor.MapStore = require("./Storage/MapStore");
ctor.DiskStore = require("./Storage/DiskStore");
module.exports = ctor;