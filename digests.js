
// ----------------
// GeneralDigest

// constructor
function GeneralDigest() {
    this.xBuf = new Array(4);
    this.xBufOff = 0;
}

GeneralDigest.prototype.update = function(in_,inOff,len) {
    if("number" == typeof in_) {
        this.xBuf[this.xBufOff++] = in_;

        if(this.xBufOff == this.xBuf.length) {
            this.processWord(this.xBuf, 0);
            this.xBufOff = 0;
        }

        this.byteCount++;
    }
    else {
        //
        // fill the current word
        //
        while((this.xBufOff != 0) && (len > 0))
        {
            this.update(in_[inOff]);
            inOff++;
            len--;
        }

        //
        // process whole words.
        //
        while(len > this.xBuf.length) {
            this.processWord(in_, inOff);

            inOff += this.xBuf.length;
            len -= this.xBuf.length;
            this.byteCount += this.xBuf.length;
        }

        //
        // load in the remainder.
        //
        while(len > 0) {
            this.update(in_[inOff]);

            inOff++;
            len--;
        }
    }
}

GeneralDigest.prototype.finish = function() {
    var bitLength = (this.byteCount << 3);
    //
    // add the pad bytes.
    //
    this.update(128);

    while(this.xBufOff != 0) {
        this.update(0);
    }

    this.processLength(bitLength);

    this.processBlock();
}

GeneralDigest.prototype.reset = function() {
    this.byteCount = 0;

    this.xBufOff = 0;
    for(var i = 0; i < this.xBuf.length; i++) {
        this.xBuf[i] = 0;
    }
}

GeneralDigest.prototype.getByteLength = function() {
    return 64; // BYTE_LENGTH
}

// ----------------
// SHA1Digest

// constructor
function SHA1Digest() {
    // super.constructor
    GeneralDigest.prototype.constructor.apply(this);

    this.DIGEST_LENGTH = 20;
    
    this.Y1 = 0x5a827999;
    this.Y2 = 0x6ed9eba1;
    this.Y3 = 0x8f1bbcdc;
    this.Y4 = 0xca62c1d6;
    
    this.X = new Array(80);

    this.reset();
}

function fGeneralDigest() {}
fGeneralDigest.prototype = GeneralDigest.prototype;

SHA1Digest.prototype = new fGeneralDigest();
SHA1Digest.prototype.consructor = SHA1Digest;

SHA1Digest.prototype.getAlgorithmName = function() {
    return "SHA-1";
}

SHA1Digest.prototype.getDigestSize = function() {
    return this.DIGEST_LENGTH;
}

SHA1Digest.prototype.processWord = function(in_, inOff)
{
    var n = in_[inOff] << 24;
    n |= (in_[++inOff] & 0xff) << 16;
    n |= (in_[++inOff] & 0xff) << 8;
    n |= (in_[++inOff] & 0xff);
    this.X[this.xOff] = n;
    
    //this.X[this.xOff] = PackbigEndianToInt(in_, inOff);
    
    if(++this.xOff == 16) {
        this.processBlock();
    }        
}

SHA1Digest.prototype.processLength = function(bitLength) {
    var X = this.X;
    
    if(this.xOff > 14) {
        this.processBlock();
    }

    //X[14] = (bitLength >>> 64);
    X[14] = 0;
    X[15] = (bitLength & 0xffffffff);
}

SHA1Digest.prototype.doFinal = function(out_, outOff) {
    this.finish();
    
    PackintToBigEndian(this.H1, out_, outOff);
    PackintToBigEndian(this.H2, out_, outOff + 4);
    PackintToBigEndian(this.H3, out_, outOff + 8);
    PackintToBigEndian(this.H4, out_, outOff + 12);
    PackintToBigEndian(this.H5, out_, outOff + 16);

    this.reset();

    return this.DIGEST_LENGTH;
}

SHA1Digest.prototype.reset = function() {

    // super.reset()
    GeneralDigest.prototype.reset.apply(this);

    this.H1 = 0x67452301;
    this.H2 = 0xefcdab89;
    this.H3 = 0x98badcfe;
    this.H4 = 0x10325476;
    this.H5 = 0xc3d2e1f0;
    
    this.xOff = 0;
    for (var i = 0; i != this.X.length; i++) {
        this.X[i] = 0;
    }
}

SHA1Digest.prototype.f = function(u,v,w) {
    return ((u & v) | ((~u) & w));
}

SHA1Digest.prototype.h = function(u,v,w) {
    return (u ^ v ^ w);
}

SHA1Digest.prototype.g = function(u,v,w) {
    return ((u & v) | (u & w) | (v & w));
}

SHA1Digest.prototype.processBlock = function() {
    var X = this.X;
    
    for(var i = 16; i < 80; i++) {
        var t = X[i - 3] ^ X[i - 8] ^ X[i - 14] ^ X[i - 16];
        X[i] = t << 1 | t >>> 31;
    }
    
    var A = this.H1;
    var B = this.H2;
    var C = this.H3;
    var D = this.H4;
    var E = this.H5;
    
    var idx = 0;
    
    //
    // round 1
    //
    for(var j = 0; j < 4; j++) {
        // E = rotateLeft(A, 5) + f(B, C, D) + E + X[idx++] + Y1
        // B = rotateLeft(B, 30)
        
        E += (A << 5 | A >>> 27) + this.f(B, C, D) + X[idx++] + this.Y1;
        B = B << 30 | B >>> 2;
        
        D += (E << 5 | E >>> 27) + this.f(A, B, C) + X[idx++] + this.Y1;
        A = A << 30 | A >>> 2;
   
        C += (D << 5 | D >>> 27) + this.f(E, A, B) + X[idx++] + this.Y1;
        E = E << 30 | E >>> 2;
   
        B += (C << 5 | C >>> 27) + this.f(D, E, A) + X[idx++] + this.Y1;
        D = D << 30 | D >>> 2;

        A += (B << 5 | B >>> 27) + this.f(C, D, E) + X[idx++] + this.Y1;
        C = C << 30 | C >>> 2;
    }
    
    //
    // round 2
    //
    for(var j = 0; j < 4; j++) {
        // E = rotateLeft(A, 5) + h(B, C, D) + E + X[idx++] + Y2
        // B = rotateLeft(B, 30)
        E += (A << 5 | A >>> 27) + this.h(B, C, D) + X[idx++] + this.Y2;
        B = B << 30 | B >>> 2;   
        
        D += (E << 5 | E >>> 27) + this.h(A, B, C) + X[idx++] + this.Y2;
        A = A << 30 | A >>> 2;
        
        C += (D << 5 | D >>> 27) + this.h(E, A, B) + X[idx++] + this.Y2;
        E = E << 30 | E >>> 2;
        
        B += (C << 5 | C >>> 27) + this.h(D, E, A) + X[idx++] + this.Y2;
        D = D << 30 | D >>> 2;

        A += (B << 5 | B >>> 27) + this.h(C, D, E) + X[idx++] + this.Y2;
        C = C << 30 | C >>> 2;
    }
    
    //
    // round 3
    //
    for(var j = 0; j < 4; j++) {
        // E = rotateLeft(A, 5) + g(B, C, D) + E + X[idx++] + Y3
        // B = rotateLeft(B, 30)
        E += (A << 5 | A >>> 27) + this.g(B, C, D) + X[idx++] + this.Y3;
        B = B << 30 | B >>> 2;
        
        D += (E << 5 | E >>> 27) + this.g(A, B, C) + X[idx++] + this.Y3;
        A = A << 30 | A >>> 2;
        
        C += (D << 5 | D >>> 27) + this.g(E, A, B) + X[idx++] + this.Y3;
        E = E << 30 | E >>> 2;
        
        B += (C << 5 | C >>> 27) + this.g(D, E, A) + X[idx++] + this.Y3;
        D = D << 30 | D >>> 2;

        A += (B << 5 | B >>> 27) + this.g(C, D, E) + X[idx++] + this.Y3;
        C = C << 30 | C >>> 2;
    }

    //
    // round 4
    //
    for(var j = 0; j <= 3; j++) {
        // E = rotateLeft(A, 5) + h(B, C, D) + E + X[idx++] + Y4
        // B = rotateLeft(B, 30)
        E += (A << 5 | A >>> 27) + this.h(B, C, D) + X[idx++] + this.Y4;
        B = B << 30 | B >>> 2;
        
        D += (E << 5 | E >>> 27) + this.h(A, B, C) + X[idx++] + this.Y4;
        A = A << 30 | A >>> 2;
        
        C += (D << 5 | D >>> 27) + this.h(E, A, B) + X[idx++] + this.Y4;
        E = E << 30 | E >>> 2;
        
        B += (C << 5 | C >>> 27) + this.h(D, E, A) + X[idx++] + this.Y4;
        D = D << 30 | D >>> 2;

        A += (B << 5 | B >>> 27) + this.h(C, D, E) + X[idx++] + this.Y4;
        C = C << 30 | C >>> 2;
    }
    
    this.H1 += A;
    this.H2 += B;
    this.H3 += C;
    this.H4 += D;
    this.H5 += E;
    
    //
    // reset start of the buffer.
    //
    this.xOff = 0;
    for(var i = 0; i < 16; i++) {
        X[i] = 0;
    }
}