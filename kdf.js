
// ----------------
// KDFParameters

// constructor
function KDFParameters(shared, iv) {
    this.shared = shared;
    this.iv = iv;
}

KDFParameters.prototype.getSharedSecret = function() {
    return this.shared;
}

KDFParameters.prototype.getIV = function() {
    return this.iv;
}

// ----------------
// BaseKDFBytesGenerator

// constructor
function BaseKDFBytesGenerator(counterStart,digest) {
    this.counterStart = counterStart;
    this.digest = digest;
}

BaseKDFBytesGenerator.prototype.init = function(param) {
    if(param instanceof KDFParameters) {
        this.shared = param.getSharedSecret();
        this.iv = param.getIV();
    }
    /*else if (param instanceof ISO18033KDFParameters) {
        ISO18033KDFParameters p = (ISO18033KDFParameters)param;
        
        shared = p.getSeed();
        iv = null;
    }
    else
    {
        throw new IllegalArgumentException("KDF parameters required for KDF2Generator");
    }*/
}

BaseKDFBytesGenerator.prototype.getDigest = function() {
    return digest;
}

BaseKDFBytesGenerator.prototype.generateBytes = function(out_,outOff,len) {
    if((out_.length - len) < outOff) {
        throw "output buffer too small";
    }
    
    var digest = this.digest;
    var iv = this.iv;

    var oBytes = len;
    var outLen = digest.getDigestSize(); 

    //
    // this is at odds with the standard implementation, the
    // maximum value should be hBits * (2^32 - 1) where hBits
    // is the digest output size in bits. We can't have an
    // array with a long index at the moment...
    //
    
    /*if(oBytes > ((2 << 32) - 1)) {
        throw "Output length too large";
    }*/

    var cThreshold = ((oBytes + outLen - 1) / outLen)>>0;

    var dig = new Array(digest.getDigestSize());

    var counter = this.counterStart;
    
    for(var i = 0; i < cThreshold; i++) {
        digest.update(this.shared, 0, this.shared.length);
        
        digest.update((counter >> 24) & 0xFF);
        digest.update((counter >> 16) & 0xFF);
        digest.update((counter >> 8) & 0xFF);
        digest.update(counter & 0xFF);
        
        if(iv != null) {
            digest.update(iv, 0, iv.length);
        }

        digest.doFinal(dig, 0);

        if(len > outLen) {
            for(var j=0; j<outLen; j++) {
                out_[outOff+j] = dig[j];
            }
            //System.arraycopy(dig, 0, out_, outOff, outLen);
            outOff += outLen;
            len -= outLen;
        }
        else {
            for(var j=0; j<len; j++) {
                out_[outOff+j] = dig[j];
            }
            //System.arraycopy(dig, 0, out_, outOff, len);
        }
        
        counter++;
    }
    
    digest.reset();

    return len;
}

var fBaseKDFBytesGenerator = function() {}
fBaseKDFBytesGenerator.prototype = BaseKDFBytesGenerator.prototype;

// ----------------
// KDF1BytesGenerator

function KDF1BytesGenerator(digest) {
    BaseKDFBytesGenerator.prototype.constructor.apply(this,new Array(0,digest));
}

KDF1BytesGenerator.prototype = new fBaseKDFBytesGenerator();
KDF1BytesGenerator.prototype.constructor = KDF1BytesGenerator;
KDF1BytesGenerator.superclass = BaseKDFBytesGenerator.prototype;

// ----------------
// KDF2BytesGenerator

function KDF2BytesGenerator(digest) {
    BaseKDFBytesGenerator.prototype.constructor.apply(this,new Array(1,digest));
}

KDF2BytesGenerator.prototype = new fBaseKDFBytesGenerator();
KDF2BytesGenerator.prototype.constructor = KDF2BytesGenerator;
KDF2BytesGenerator.superclass = BaseKDFBytesGenerator.prototype;
