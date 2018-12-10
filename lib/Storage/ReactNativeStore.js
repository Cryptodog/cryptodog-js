function ReactNativeStore() {
  this.as = require("react-native").AsyncStorage;
}

ReactNativeStore.prototype.setItem = function(key, value) {
  return this.as.setItem(key, JSON.stringify(value));
}

ReactNativeStore.prototype.getItem = function(key) {
  var $this = this;
  return new Promise(function (y, n) {
    $this.as.getItem(key)
    .then(function(str) {
      var o = JSON.parse(str);
      y(o);
    })
    .catch(function(err) {
      y(undefined);
    });
  });
}

ReactNativeStore.prototype.clear = function(key) {
  return this.as.clear();
}

module.exports = ReactNativeStore;
