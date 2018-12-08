const path = require("path");
const fs   = require("fs");

function DiskStore(pt) {
  this.p = pt.split(path.sep);
  if (this.p[this.p.length-1] == '') {
    this.p.pop();
  }
  try {
    var stat = fs.statSync(pt);
  } catch (e) {
    if (e) {
      fs.mkdirSync(pt);
    }
  }
}

DiskStore.prototype.itemString = function(c) {
  var p = this.p.slice(0, this.p.length);
  p.push(c)
  return p.join(path.sep);
}

DiskStore.prototype.getItem = function(k) {
  var $this = this;
  return new Promise(function (y, n) {
    var pth = $this.itemString(k);
    var dat
    try {
      dat = fs.readFileSync(pth);
      y(JSON.parse(dat.toString('utf8')));
    } catch (e) {
      y(null);
    }
  });
}

DiskStore.prototype.setItem = function(k,v) {
  var $this = this;
  return new Promise(function (y, n) {
    var pth = $this.itemString(k);
    fs.writeFile(pth, JSON.stringify(v), function(e) {
      y();
    })
  });
}

DiskStore.prototype.clear = function() {
  var $this = this;
  var item = fs.readdirSync($this.p.join(path.sep));

  item.forEach(function(i) {
    var p = $this.itemString(i);
    fs.unlinkSync(p);
  });
}

module.exports = DiskStore;