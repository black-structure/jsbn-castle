
// ----------------
// HMac

// constructor
function HMac(digest, byteLength) {
    if("number" != typeof byteLength) {
        byteLength = digest.getByteLength();
    }
    
    this.digest = digest;
    this.digestSize = digest.getDigestSize();

    this.blockLength = byteLength;

    //this.inputPad = new Array(this.blockLength);
    //this.outputPad = new Array(this.blockLength);
    
    this.IPAD = 0x36;
    this.OPAD = 0x5C;
}

HMac.prototype.getAlgorithmName = function() {
    return this.digest.getAlgorithmName() + "/HMAC";
}

HMac.prototype.getUnderlyingDigest = function() {
    return this.digest;
}

HMac.prototype.getByteLength = function() {
    return this.digest.getByteLength();
}

HMac.prototype.init = function(params) {
    var digest = this.digest;
    var inputPad;
    
    digest.reset();
    var key = params.getKey();
    
    if(key.length > this.blockLength) {
        inputPad = new Array(this.blockLength);
        digest.update(key, 0, key.length);
        digest.doFinal(inputPad, 0);
        for(var i = this.digestSize; i < inputPad.length; i++) {
            inputPad[i] = 0;
        }
    }
    else {
        inputPad = key.slice(0, key.length);
        inputPad.length = this.blockLength;
        for(var i = key.length; i < inputPad.length; i++) {
            inputPad[i] = 0;
        }
    }

    var outputPad = inputPad.slice(0, inputPad.length);

    for(var i = 0; i < inputPad.length; i++) {
        inputPad[i] ^= this.IPAD;
    }

    for(var i = 0; i < outputPad.length; i++) {
        outputPad[i] ^= this.OPAD;
    }

    digest.update(inputPad, 0, inputPad.length);
    
    this.inputPad = inputPad;
    this.outputPad = outputPad;
}

HMac.prototype.getMacSize = function() {
    return this.digestSize;
}

HMac.prototype.update = function(in_,inOff,len) {
    this.digest.update(in_,inOff,len);
}

HMac.prototype.doFinal = function(out_,outOff) {
    var digest = this.digest;
    var tmp = new Array(this.digestSize);
    digest.doFinal(tmp, 0);

    digest.update(this.outputPad, 0, this.outputPad.length);
    digest.update(tmp, 0, tmp.length);

    var len = digest.doFinal(out_, outOff);

    this.reset();

    return len;
}

HMac.prototype.reset = function() {
    this.digest.reset();
    this.digest.update(this.inputPad, 0, this.inputPad.length);
}