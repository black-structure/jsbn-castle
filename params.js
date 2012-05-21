
// ----------------
// KeyParameter

// constructor
function KeyParameter(key, keyOff, keyLen) {
    if("number" != typeof keyOff) {
        keyOff = 0;
        keyLen = key.length;
    }
    
    this.key = key.slice(keyOff, keyOff+keyLen);
}

KeyParameter.prototype.getKey = function() {
    return this.key;
}

