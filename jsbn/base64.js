var b64map="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
var b64pad="=";

// convert a hex string to base64
function hex2b64(h) {
  var i;
  var c;
  var ret = "";
  var n = h.length;
  for(i = 0; i+3 <= n; i+=3) {
    c = parseInt(h.substring(i,i+3),16);
    ret += b64map.charAt(c >>> 6) + b64map.charAt(c & 63);
  }
  if(i+1 == h.length) {
    c = parseInt(h.substring(i,i+1),16);
    ret += b64map.charAt(c << 2);
  }
  else if(i+2 == h.length) {
    c = parseInt(h.substring(i,i+2),16);
    ret += b64map.charAt(c >>> 2) + b64map.charAt((c & 3) << 4);
  }
  while((ret.length & 3) > 0) ret += b64pad;
  return ret;
}

// convert a base64 string to hex
function b64tohex(s) {
  var ret = ""
  var i;
  var k = 0; // b64 state, 0-3
  var slop;
  var n = s.length;
  for(i = 0; i < n; ++i) {
    if(s.charAt(i) == b64pad) break;
    v = b64map.indexOf(s.charAt(i));
    if(v < 0) continue;
    if(k == 0) {
      ret += int2char(v >>> 2);
      slop = v & 3;
      k = 1;
    }
    else if(k == 1) {
      ret += int2char((slop << 2) | (v >>> 4));
      slop = v & 0xf;
      k = 2;
    }
    else if(k == 2) {
      ret += int2char(slop);
      ret += int2char(v >>> 2);
      slop = v & 3;
      k = 3;
    }
    else {
      ret += int2char((slop << 2) | (v >>> 4));
      ret += int2char(v & 0xf);
      k = 0;
    }
  }
  if(k == 1)
    ret += int2char(slop << 2);
  return ret;
}      	

// convert a byte array to base64
function BAtob64(a,from,to) {
  var h = "";
  var i;
  for(i = from; i < to; i++) {
    h += int2char(a[i] >>> 4);
    h += int2char(a[i] & 0xf);
  }
  return hex2b64(h);
}

// convert a base64 to array
function b64toBA(s) {
  var a = new Array;
  var i;
  var j = 0;
  var k = 0; // b64 state, 0-3
  var slop;
  var n = s.length;
  for(i = 0; i < n; ++i) {
    if(s.charAt(i) == b64pad) break;
    v = b64map.indexOf(s.charAt(i));
    if(v < 0) continue;
    if(k == 0) {
      a[j] = (v >>> 2) << 4;
      slop = v & 3;
      k = 1;
    }
    else if(k == 1) {
      a[j++] |= (slop << 2) | (v >>> 4);
      slop = v & 0xf;
      k = 2;
    }
    else if(k == 2) {
      a[j++] = (slop << 4) | (v >>> 2);
      slop = v & 3;
      k = 3;
    }
    else {
      a[j++] = (((slop << 2) | (v >>> 4)) << 4) | (v & 0xf);
      k = 0;
    }
  }
  if(k == 1)
    a[j] |= slop << 2;
  return a;
}

// convert a unicode string to base64
function strtob64(s) {
  var i;
  var a = new Array;
  var n = s.length;
  for(i = 0; i < n; ++i) {
    var t = s.charCodeAt(i);
    a[2*i] = t & 0xff;
    a[2*i+1] = t >>> 8;
  }
  return BAtob64(a,0,2*n);
}

// convert a base64 to unicode string
function b64tostr(s) {
  var a = b64toBA(s);
  var n = a.length;
  var ret = "";
  var i;
  for(i = 0; i < n; i+=2) {
    var t = a[i] | (a[i+1] << 8);
    ret += String.fromCharCode(t);
  }
  return ret;
}