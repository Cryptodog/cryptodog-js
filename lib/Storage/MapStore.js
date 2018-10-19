function MapStore() {
  this.m = {};
}

MapStore.prototype.getItem = function(k) {
  var $this = this;
  return new Promise(function(y,n) {
    y($this.m[k]);
  });
}

MapStore.prototype.setItem = function(k,v) {
  var $this = this;
  return new Promise(function(y,n) {
    $this.m[k] = v;
    y();
  });
}

MapStore.prototype.clear = function() {
  this.m = null;
  this.m = {};
}