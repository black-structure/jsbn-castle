// Named EC curves

// Requires ec.js, jsbn.js, and jsbn2.js

// ----------------
// SECNamedCurves

SECNamedCurves = {};

SECNamedCurves.fromHex = function(s) { return new BigInteger(s, 16); }

SECNamedCurves.secp128r1 = function() {
    // p = 2^128 - 2^97 - 1
    var p = this.fromHex("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF");
    var a = this.fromHex("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC");
    var b = this.fromHex("E87579C11079F43DD824993C2CEE5ED3");
    //byte[] S = Hex.decode("000E0D4D696E6768756151750CC03A4473D03679");
    var n = this.fromHex("FFFFFFFE0000000075A30D1B9038A115");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04"
                + "161FF7528B899B2D0C28607CA52C5B86"
                + "CF5AC8395BAFEB13C02DA292DDED7A83");
    return new ECDomainParameters(curve, G, n, h);
}

SECNamedCurves.secp160k1 = function() {
    // p = 2^160 - 2^32 - 2^14 - 2^12 - 2^9 - 2^8 - 2^7 - 2^3 - 2^2 - 1
    var p = this.fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73");
    var a = BigInteger.ZERO;
    var b = this.fromHex("7");
    //byte[] S = null;
    var n = this.fromHex("0100000000000000000001B8FA16DFAB9ACA16B6B3");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04"
                + "3B4C382CE37AA192A4019E763036F4F5DD4D7EBB"
                + "938CF935318FDCED6BC28286531733C3F03C4FEE");
    return new ECDomainParameters(curve, G, n, h);
}

SECNamedCurves.secp160r1 = function() {
    // p = 2^160 - 2^31 - 1
    var p = this.fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF");
    var a = this.fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC");
    var b = this.fromHex("1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45");
    //byte[] S = Hex.decode("1053CDE42C14D696E67687561517533BF3F83345");
    var n = this.fromHex("0100000000000000000001F4C8F927AED3CA752257");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04"
                + "4A96B5688EF573284664698968C38BB913CBFC82"
                + "23A628553168947D59DCC912042351377AC5FB32");
    return new ECDomainParameters(curve, G, n, h);
}

SECNamedCurves.secp192k1 = function() {
    // p = 2^192 - 2^32 - 2^12 - 2^8 - 2^7 - 2^6 - 2^3 - 1
    var p = this.fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37");
    var a = BigInteger.ZERO;
    var b = this.fromHex("3");
    //byte[] S = null;
    var n = this.fromHex("FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04"
                + "DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D"
                + "9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D");
    return new ECDomainParameters(curve, G, n, h);
}

SECNamedCurves.secp192r1 = function() {
    // p = 2^192 - 2^64 - 1
    var p = this.fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF");
    var a = this.fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC");
    var b = this.fromHex("64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1");
    //byte[] S = Hex.decode("3045AE6FC8422F64ED579528D38120EAE12196D5");
    var n = this.fromHex("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04"
                + "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012"
                + "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811");
    return new ECDomainParameters(curve, G, n, h);
}

SECNamedCurves.secp224r1 = function() {
    // p = 2^224 - 2^96 + 1
    var p = this.fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001");
    var a = this.fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE");
    var b = this.fromHex("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4");
    //byte[] S = Hex.decode("BD71344799D5C7FCDC45B59FA3B9AB8F6A948BC5");
    var n = this.fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04"
                + "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21"
                + "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34");
    return new ECDomainParameters(curve, G, n, h);
}

SECNamedCurves.secp256r1 = function() {
    // p = 2^224 (2^32 - 1) + 2^192 + 2^96 - 1
    var p = this.fromHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
    var a = this.fromHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");
    var b = this.fromHex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
    //byte[] S = Hex.decode("C49D360886E704936A6678E1139D26B7819F7E90");
    var n = this.fromHex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    var h = BigInteger.ONE;
    var curve = new ECCurveFp(p, a, b);
    var G = curve.decodePointHex("04"
                + "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
                + "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
    return new ECDomainParameters(curve, G, n, h);
}

SECNamedCurves.sect163k1 = function() {
    var m = 163;
    var k1 = 3;
    var k2 = 6;
    var k3 = 7;
    var a = BigInteger.ONE;
    var b = BigInteger.ONE;
    var S = null;
    var n = this.fromHex("04000000000000000000020108A2E0CC0D99F8A5EF");
    var h = BigInteger.TWO;
    var curve = new ECCurveF2m(m, k1, k2, k3, a, b, n, h);
    curve.name = 'sect163k1';
    //var G = curve.decodePointHex("03"
    //+ "02FE13C0537BBC11ACAA07D793DE4E6D5E5C94EEE8");
    var G = curve.decodePointHex("04"
        + "02FE13C0537BBC11ACAA07D793DE4E6D5E5C94EEE8"
        + "0289070FB05D38FF58321F2E800536D538CCDAA3D9");
    return new ECDomainParameters(curve, G, n, h, S);
}

SECNamedCurves.sect233k1 = function() {
    var m = 233;
    var k = 74;
    var a = BigInteger.ZERO;
    var b = BigInteger.ONE;
    var S = null;
    var n = this.fromHex("8000000000000000000000000000069D5BB915BCD46EFB1AD5F173ABDF");
    var h = BigInteger.FOUR; 

    var curve = new ECCurveF2m(m, k, a, b, n, h);
    curve.name = 'sect233k1';
    //var G = curve.decodePointHex("02"
    //+ "017232BA853A7E731AF129F22FF4149563A419C26BF50A4C9D6EEFAD6126");
    var G = curve.decodePointHex("04"
        + "017232BA853A7E731AF129F22FF4149563A419C26BF50A4C9D6EEFAD6126"
        + "01DB537DECE819B7F70F555A67C427A8CD9BF18AEB9B56E0C11056FAE6A3");
    return new ECDomainParameters(curve, G, n, h, S);
}

SECNamedCurves.table = {
    'secp128r1' : function() { return this.secp128r1(); },
    'secp160k1' : function() { return this.secp160k1(); },
    'secp160r1' : function() { return this.secp160r1(); },
    'secp192k1' : function() { return this.secp192k1(); },
    'secp192r1' : function() { return this.secp192r1(); },
    'secp224r1' : function() { return this.secp224r1(); },
    'secp256r1' : function() { return this.secp256r1(); },
    'sect163k1' : function() { return this.sect163k1(); },
    'sect233k1' : function() { return this.sect233k1(); }
    };
SECNamedCurves.table_pre = {};

function SECNamedCurves.get(name) {
    if(!(name in this.table)) return null;
    else {
        if(name in this.table_pre) return this.table_pre[name];
        else {
            var params = this.table[name] ();
            this.table_pre[name] = params;
            return params;
        }
    }
}
