
// Elliptic Diffie-Hellman stuff

// ----------------
// ECDomainParameters

// constructor
function ECDomainParameters(curve, G, n, h, seed) {
    this.curve = curve;
    this.G = G;
    this.n = n;
    if(h instanceof BigInteger) {
        this.h = h;
    }
    else {
        this.h = null;
    }
    if(seed instanceof Array) {
        this.seed = seed;
    }
    else {
        this.seed = null;
    }
}

ECDomainParameters.prototype.getCurve = function() {
    return this.curve;
}

ECDomainParameters.prototype.getG = function() {
    return this.G;
}

ECDomainParameters.prototype.getN = function() {
    return this.n;
}

ECDomainParameters.prototype.getH = function() {
    return this.h;
}

ECDomainParameters.prototype.getSeed = function() {
    return this.seed;
}

// ----------------
// ECKeyParameters

// constructor
function ECKeyParameters(isPrivate, params) {
    this.privateKey = isPrivate;
    this.params = params;
}

ECKeyParameters.prototype.getParameters = function() {
    return this.params;
}

ECKeyParameters.prototype.isPrivate = function() {
    return this.privateKey;
}

var fECKeyParameters = function() {}
fECKeyParameters.prototype = ECKeyParameters.prototype;

// ----------------
// ECPrivateKeyParameters

// constructor
function ECPrivateKeyParameters(d,params) {
    ECKeyParameters.prototype.constructor.apply(this,new Array(true,params));
    this.d = d;
}

ECPrivateKeyParameters.prototype = new fECKeyParameters;
ECPrivateKeyParameters.prototype.constructor = ECPrivateKeyParameters;

ECPrivateKeyParameters.prototype.getD = function() {
    return this.d;
}

// ----------------
// ECPublicKeyParameters

// constructor
function ECPublicKeyParameters(Q,params) {
    ECKeyParameters.prototype.constructor.apply(this,new Array(false,params));
    this.Q = Q;
}

ECPublicKeyParameters.prototype = new fECKeyParameters;
ECPublicKeyParameters.prototype.constructor = ECPublicKeyParameters;

ECPublicKeyParameters.prototype.getQ = function() {
    return this.Q;
}

// ----------------
// ECPrivateToPublic helper
function ECPrivateToPublic(priv) {
    var params = priv.getParameters();
    return new ECPublicKeyParameters(params.getG().multiply(priv.getD()), params);
}

// ----------------
// ECKeyGenerationParameters

function ECKeyGenerationParameters(domainParams,random) {
    this.random = random;
    this.domainParams = domainParams;
    this.strength = domainParams.getN().bitLength();
}

ECKeyGenerationParameters.prototype.getRandom = function() {
    return this.random;
}

ECKeyGenerationParameters.prototype.getDomainParameters = function() {
    return this.domainParams;
}

ECKeyGenerationParameters.prototype.getStrength = function(params) {
    return this.strength;
}

// ----------------
// ECKeyPairGenerator

function ECKeyPairGenerator() {}

ECKeyPairGenerator.prototype.init = function(param) {
    // param is instanceof ECKeyGenerationParameters
    this.random = param.getRandom();
    this.params = param.getDomainParameters();
}

ECKeyPairGenerator.prototype.generateKeyPair = function() {
    var params = this.params, random = this.random;
    var n = params.getN();
    var nBitLength = n.bitLength();
    var d;
    var Q;
    do {
        d = new BigInteger(nBitLength, random);
        Q = params.getG().multiply(d);
    }
    while(Q.isInfinity());
    //while(d.equals(BigInteger.ZERO)  || (d.compareTo(n) >= 0));
    
    return new AsymmetricCipherKeyPair(new ECPublicKeyParameters(Q, params), new ECPrivateKeyParameters(d, params));
}

// ----------------
// ECDHBasicAgreement

// constructor
function ECDHBasicAgreement() { }

ECDHBasicAgreement.prototype.init = function(param) {
    // param must be instanceof ECPrivateKeyParameters
    
    if(!(param instanceof ECPrivateKeyParameters)) {
        throw "ECEngine expects ECPrivateKeyParameters";
    }

    this.key = param;
}

ECDHBasicAgreement.prototype.calculateAgreement = function(pub) {
    // pub must be instance of ECPublicKeyParameters
    
    var P = pub.getQ().multiply(this.key.getD());
    return P.getX().toBigInteger();
}