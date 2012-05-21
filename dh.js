
// Diffie-Hellman related stuff

// ----------------
// DHParameters

// constructor
function DHParameters(p,g,q, a,b,c,d) {
    var m;
    var l;
    var j;
    var validation;
    
    var DEFAULT_MINIMUM_LENGTH = 160;
    
    this.DEFAULT_MINIMUM_LENGTH = DEFAULT_MINIMUM_LENGTH;
    
    var arglen = arguments.length;
    
    if(arglen < 4 || (arglen == 4 && typeof a == "number")) { // DHParameters(p,g,q,l)
        l = a || 0;
        m = this.getDefaultMParam(l);
        j = null;
        validation = null;
    }
    else if(typeof a == "number" && typeof b == "number") { // DHParameters(p,g,q,m,l,j,validaion)
        m = a;
        l = b;
        j = c;
        validation = d;
    }
    else if(arglen == 5) { // DHParameters(p,g,q,j,validation)
        m = DEFAULT_MINIMUM_LENGTH;
        l = 0;
        j = a;
        validation = b;
    }
    
    if(l != 0) {
        if(l >= p.bitLength()) {
            throw "when l value specified, it must be less than bitlength(p)";
        }
        if(l < m) {
            throw "when l value specified, it may not be less than m value";
        }
    }

    this.g = g;
    this.p = p;
    this.q = q;
    this.m = m;
    this.l = l;
    this.j = j;
    this.validation = validation;
}

DHParameters.prototype.getP = function() {
    return this.p;
}

DHParameters.prototype.getG = function() {
    return this.g;
}

DHParameters.prototype.getQ = function() {
    return this.q;
}

// Return the subgroup factor J.
DHParameters.prototype.getJ = function() {
    return this.j;
}

// Return the minimum length of the private value.
DHParameters.prototype.getM = function() {
    return this.m;
}

// Return the private value length in bits - if set, zero otherwise
DHParameters.prototype.getL = function() {
    return this.l;
}

DHParameters.prototype.getValidationParameters = function() {
    return this.validation;
}

DHParameters.prototype.equals = function(obj) {
    var p = this.p;
    var g = this.g;
    var q = this.q;
    
    if (!(obj instanceof DHParameters)) {
        return false;
    }

    var pm = obj;

    if(this.getQ() != null) {
        if(!this.getQ().equals(pm.getQ())) {
            return false;
        }
    }
    else {
        if(pm.getQ() != null) {
            return false;
        }
    }

    return pm.getP().equals(p) && pm.getG().equals(g);
}

DHParameters.prototype.hashCode = function() {
    return this.getP().hashCode() ^ this.getG().hashCode() ^ (this.getQ() != null ? this.getQ().hashCode() : 0);
}

// ----------------
// DHValidationParameters

// constructor
function DHValidationParameters(seed,counter) {
    this.seed = seed;
    this.counter = counter;
}

DHValidationParameters.prototype.getCounter = function() {
    return this.counter;
}

DHValidationParameters.prototype.getSeed = function() {
    return this.seed;
}

/*DHValidationParameters.prototype.equals = function(o) {
    if(!(o instanceof DHValidationParameters)) {
        return false;
    }

    var other = o;

    if(other.counter != this.counter)
    {
        return false;
    }

    return Arrays.areEqual(this.seed, other.seed);
}

DHValidationParameters.prototype.hashCode = function() {
    return this.counter ^ seed.hashCode();
}*/

// ----------------
// DHParametersHelper

function DHParametersHelper() {}

DHParametersHelper.generateSafePrimes = function(size, certainty, random) {
    var p, q;
    var qLength = size - 1;

    for(;;) {
        q = new BigInteger(qLength, 2, random);

        // p <- 2q + 1
        p = q.shiftLeft(1).add(BigInteger.ONE);

        if(p.isProbablePrime(certainty) && (certainty <= 2 || q.isProbablePrime(certainty))) {
            break;
        }
    }

    return new Array(p, q);
}

DHParametersHelper.selectGenerator = function(p, q, random) {
    var pMinusTwo = p.subtract(BigInteger.TWO);
    var g;

    /*
     * RFC 2631 2.2.1.2 (and see: Handbook of Applied Cryptography 4.81)
     */
    do {
        var h = BigIntegers.createRandomInRange(BigInteger.TWO, pMinusTwo, random);
        g = h.modPow(BigInteger.TWO, p);
    }
    while (g.equals(BigInteger.ONE));

    return g;
}

// ----------------
// DHParametersGenerator

function DHParametersGenerator() {}

DHParametersGenerator.prototype.init = function(size,certainty,random) {
    this.size = size;
    this.certainty = certainty;
    this.random = random;
}

DHParametersGenerator.prototype.generateParameters = function() {
    var size = this.size;
    var certainty = this.certainty;
    var random = this.random;
    
    var safePrimes = DHParametersHelper.generateSafePrimes(size, certainty, random);

    var p = safePrimes[0];
    var q = safePrimes[1];
    var g = DHParametersHelper.selectGenerator(p, q, random);

    return new DHParameters(p, g, q, BigInteger.TWO, null);
}

// ----------------
// DHKeyParameters

// constructor
function DHKeyParameters(isPrivate, params) {
    this.privateKey = isPrivate;
    this.params = params;
}

DHKeyParameters.prototype.getParameters = function() {
    return this.params;
}

DHKeyParameters.prototype.isPrivate = function() {
    return this.privateKey;
}

DHKeyParameters.prototype.equals = function(obj) {
    if(!(obj instanceof DHKeyParameters)) {
        return false;
    }

    var dhKey = obj;
    
    if(this.params == null) {
        return dhKey.getParameters() == null;
    }
    else {
        return this.params.equals(dhKey.getParameters());
    }
}

DHKeyParameters.prototype.hashCode = function() {
    var code = this.isPrivate() ? 0 : 1;
    
    if(this.params != null) {
        code ^= this.params.hashCode();
    }
    
    return code;
}

var fDHKeyParameters = function() {}
fDHKeyParameters.prototype = DHKeyParameters.prototype;

// ----------------
// DHPrivateKeyParameters

// constructor
function DHPrivateKeyParameters(x,params) {
    DHKeyParameters.prototype.constructor.apply(this,new Array(true,params));
    this.x = x;
}

DHPrivateKeyParameters.prototype = new fDHKeyParameters;
DHPrivateKeyParameters.prototype.constructor = DHPrivateKeyParameters;

DHPrivateKeyParameters.prototype.getX = function() {
    return this.x;
}

DHPrivateKeyParameters.prototype.hashCode = function() {
    var h = DHKeyParameters.prototype.hashCode.apply(this);
    return h ^ x.hashCode();
}

DHPrivateKeyParameters.prototype.equals = function(obj)
{
    if(!(obj instanceof DHPrivateKeyParameters)) {
        return false;
    }

    var other = obj;

    var arg = new Array(1); arg[0] = obj;
    
    return other.getX().equals(this.x) && DHKeyParameters.prototype.equals.apply(this,arg);
}

// ----------------
// DHPublicKeyParameters

// constructor
function DHPublicKeyParameters(y,params) {
    DHKeyParameters.prototype.constructor.apply(this,new Array(false,params));
    this.y = y;
}

DHPublicKeyParameters.prototype = new fDHKeyParameters;
DHPublicKeyParameters.prototype.constructor = DHPublicKeyParameters;

DHPublicKeyParameters.prototype.getY = function() {
    return this.y;
}

DHPublicKeyParameters.prototype.hashCode = function() {
    var h = DHKeyParameters.prototype.hashCode.apply(this);
    return h ^ y.hashCode();
}

DHPublicKeyParameters.prototype.equals = function(obj)
{
    if(!(obj instanceof DHPublicKeyParameters)) {
        return false;
    }

    var other = obj;

    var arg = new Array(1); arg[0] = obj;
    
    return other.getY().equals(this.y) && DHKeyParameters.prototype.equals.apply(this,arg);
}

// ----------------
// DHKeyGeneratorHelper

function DHKeyGeneratorHelper() {}

DHKeyGeneratorHelper.calculatePrivate = function(dhParams, random) {
    var p = dhParams.getP();
    var limit = dhParams.getL();
    
    if(limit != 0) {
        return new BigInteger(limit, random).setBit(limit - 1);
    }

    var min = BigInteger.TWO;
    var m = dhParams.getM();
    
    
    
    if(m != 0) {
        min = BigInteger.ONE.shiftLeft(m - 1);
    }

    var max = p.subtract(BigInteger.TWO);
    var q = dhParams.getQ();
    if(q != null) {
        max = q.subtract(BigInteger.TWO);
    }

    return BigIntegers.createRandomInRange(min, max, random);
}

DHKeyGeneratorHelper.calculatePublic = function(dhParams,x) {
    return dhParams.getG().modPow(x, dhParams.getP());
}

// ----------------
// AsymmetricCipherKeyPair

function AsymmetricCipherKeyPair(publicParam,privateParam) {
    this.publicParam = publicParam;
    this.privateParam = privateParam;
}

AsymmetricCipherKeyPair.prototype.getPublic = function() {
    return this.publicParam;
}

AsymmetricCipherKeyPair.prototype.getPrivate = function() {
    return this.privateParam;
}

// ----------------
// DHKeyGenerationParameters

function DHKeyGenerationParameters(random,params) {
    this.random = random;
    this.params = params;
    this.strength = this.getStrength(params);
}

DHKeyGenerationParameters.prototype.getRandom = function() {
    return this.random;
}

DHKeyGenerationParameters.prototype.getParameters = function() {
    return this.params;
}

DHKeyGenerationParameters.prototype.getStrength = function(params) {
    if(params == null) {
        return this.strength;
    }
    else {
        return this.params.getL() != 0 ? this.params.getL() : this.params.getP().bitLength();
    }
}

// ----------------
// DHKeyPairGenerator

function DHKeyPairGenerator() {}

DHKeyPairGenerator.prototype.init = function(param) {
    // param is instanceof DHKeyGenerationParameters
    this.param = param;
}

DHKeyPairGenerator.prototype.generateKeyPair = function() {
    var param = this.param;
    
    var dhp = param.getParameters();

    var x = DHKeyGeneratorHelper.calculatePrivate(dhp, param.getRandom()); 
    var y = DHKeyGeneratorHelper.calculatePublic(dhp, x);
    
    return new AsymmetricCipherKeyPair(new DHPublicKeyParameters(y, dhp), new DHPrivateKeyParameters(x, dhp));
}

// ----------------
// DHBasicAgreement

// constructor
function DHBasicAgreement() { }

DHBasicAgreement.prototype.init = function(param) {
    // param must be instanceof DHPrivateKeyParameters
    if(!(param instanceof DHPrivateKeyParameters)) {
        throw "DHEngine expects DHPrivateKeyParameters";
    }

    this.key = param;
    this.dhParams = this.key.getParameters();
}

DHBasicAgreement.prototype.calculateAgreement = function(pub) {
    // pub must be instance of DHPublicKeyParameters
    // dhParams must be instance of DHParameters
    
    if(!pub.getParameters().equals(this.dhParams)) {
        throw "Diffie-Hellman public key has wrong parameters.";
    }

    return pub.getY().modPow(this.key.getX(), this.dhParams.getP());
}