
// INTEGRATED ENCRYPTION SCHEME

// ----------------
// IESParameters

// constructor
function IESParameters(derivation,encoding,macKeySize) {
    this.derivation = derivation;
    this.encoding = encoding;
    this.macKeySize = macKeySize;
}

IESParameters.prototype.getDerivationV = function()
{
    return this.derivation;
}

IESParameters.prototype.getEncodingV = function()
{
    return this.encoding;
}

IESParameters.prototype.getMacKeySize = function()
{
    return this.macKeySize;
}

var fIESParameters = function() {}
fIESParameters.prototype = IESParameters.prototype;

// ----------------
// IESWithCipherParameters

// constructor
function IESWithCipherParameters(derivation,encoding,macKeySize,cipherKeySize) {
    IESParameters.prototype.constructor.apply(this,new Array(derivation,encoding,macKeySize));
    this.cipherKeySize = cipherKeySize;
}

IESWithCipherParameters.prototype = new fIESParameters();
IESWithCipherParameters.prototype.constructor = IESWithCipherParameters;

// ----------------
// IESEngine

// constructor
function IESEngine(agree, kdf, mac, cipher) {
    this.agree = agree;
    this.kdf = kdf;
    this.mac = mac;
    this.macBuf = new Array(this.mac.getMacSize());
    this.cipher = cipher;
}

IESEngine.prototype.init = function(forEncryption, privParam, pubParam, param) {
    // param is instance of IESParameters
    this.forEncryption = forEncryption;
    this.privParam = privParam;
    this.pubParam = pubParam;
    this.param = param;
}

IESEngine.prototype.decryptBlock = function(in_enc, inOff, inLen, z) {
    var M = null;
    var macKey = null;
    var kParam = new KDFParameters(z, this.param.getDerivationV());
    var macKeySize = this.param.getMacKeySize();
    
    this.kdf.init(kParam);
    
    inLen -= this.mac.getMacSize();
    
    if(this.cipher == null) { // stream mode
        var buf = this.generateKdfBytes(kParam, inLen + (macKeySize / 8))

        var M = new Array(inLen);

        for(var i = 0; i != inLen; i++) {
            M[i] = (in_enc[inOff + i] ^ buf[i]) & 0xFF;
        }

        macKey = new KeyParameter(buf, inLen, (macKeySize / 8));
    }
    else {
        var cipherKeySize = this.param.getCipherKeySize();
        var buf = this.generateKdfBytes(kParam, (cipherKeySize / 8) + (macKeySize / 8));

        this.cipher.init(false, new KeyParameter(buf, 0, (cipherKeySize / 8)));

        var tmp = new Array(cipher.getOutputSize(inLen));

        var len = this.cipher.processBytes(in_enc, inOff, inLen, tmp, 0);

        len += this.cipher.doFinal(tmp, len);

        M = tmp.slice(0,len);

        macKey = new KeyParameter(buf, (cipherKeySize / 8), (macKeySize / 8));
    }

    var macIV = this.param.getEncodingV();

    this.mac.init(macKey);
    this.mac.update(in_enc, inOff, inLen);
    if(macIV) this.mac.update(macIV, 0, macIV.length);
    this.mac.doFinal(this.macBuf, 0);

    inOff += inLen;

    for(var t = 0; t < this.macBuf.length; t++) {
        if(this.macBuf[t] != in_enc[inOff + t]) {
            //throw "Mac codes failed to equal.";
            return null;
        }
    }
   
    return M;
}

IESEngine.prototype.encryptBlock = function(in_dec, inOff, inLen, z) {
    var param = this.param;
    var mac = this.mac;
    var C = null;
    var macKey = null;
    var kParam = new KDFParameters(z, param.getDerivationV());
    var c_text_length = 0;
    var macKeySize = this.param.getMacKeySize();
    
    if(this.cipher == null) { // stream mode
        var buf = this.generateKdfBytes(kParam, inLen + (macKeySize / 8));
        
        C = new Array(inLen + mac.getMacSize());
        c_text_length = inLen;

        for (var i = 0; i != inLen; i++) {
            C[i] = (in_dec[inOff + i] ^ buf[i]) & 0xFF;
        }

        macKey = new KeyParameter(buf, inLen, (macKeySize / 8));
    }
    else {
        var cipherKeySize = param.getCipherKeySize();
        var buf = this.generateKdfBytes(kParam, (cipherKeySize / 8) + (macKeySize / 8));

        this.cipher.init(true, new KeyParameter(buf, 0, (cipherKeySize / 8)));

        c_text_length = this.cipher.getOutputSize(inLen);

        var tmp = new Array(c_text_length);

        var len = this.cipher.processBytes(in_dec, inOff, inLen, tmp, 0);

        len += this.cipher.doFinal(tmp, len);

        c_text_length = len;

        C = tmp.slice(0,len);
        C.length = len + mac.getMacSize();

        macKey = new KeyParameter(buf, (cipherKeySize / 8), (macKeySize / 8));
    }

    var macIV = this.param.getEncodingV();

    mac.init(macKey);
    mac.update(C, 0, c_text_length);
    if(macIV) mac.update(macIV, 0, macIV.length);
    //
    // return the message and it's MAC
    //
    mac.doFinal(C, c_text_length);
    return C;
}

IESEngine.prototype.generateKdfBytes = function(kParam, length) {
    var buf = new Array(length);

    this.kdf.init(kParam);

    this.kdf.generateBytes(buf, 0, buf.length);

    return buf;
}

IESEngine.prototype.processBlock = function(in_, inOff, inLen) {
    this.agree.init(this.privParam);

    var z = this.agree.calculateAgreement(this.pubParam);

    if(this.forEncryption) {
        return this.encryptBlock(in_, inOff, inLen, z.toByteArray());
    }
    else {
        return this.decryptBlock(in_, inOff, inLen, z.toByteArray());
    }
}

// ----------------
// IES implementations

// Discrete Logarithm IES
function IES() {
    return new IESEngine(new DHBasicAgreement(),
            new KDF2BytesGenerator(new SHA1Digest()),
            new HMac(new SHA1Digest()));
}

// Elliptic Curve IES
function ECIES() {
    return new IESEngine(
            new ECDHBasicAgreement(),
            new KDF2BytesGenerator(new SHA1Digest()),
            new HMac(new SHA1Digest()));
}