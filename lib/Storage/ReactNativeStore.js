function ReactNativeStore() {
  this.as = require("react-native").AsyncStorage;
}

ReactNativeStore.prototype.setItem = function(key, value) {
  return this.as.setItem(key, value);
}

ReactNativeStore.prototype.getItem = function(key) {
  return this.as.getItem(key);
}

ReactNativeStore.prototype.clear = function(key) {
  return this.as.clear();
}

module.exports = ReactNativeStore;
