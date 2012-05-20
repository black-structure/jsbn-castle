// Basic Javascript Elliptic Curve implementation
// Ported loosely from BouncyCastle's Java EC code
// F2m curves implementation

// Requires jsbn.js and jsbn2.js

// ----------------
// ...
function prepareByteArray(b) {
    if(b[0] & 0x80) {
        var t = new Array(b.length+1);
        t[0]=0;
        for(var i=0; i<b.length; i++)
            t[1+i] = b[i];
        b = t;
    }
    return b;
}

// ----------------
// IntArray

// constructor
function IntArray(a,b,c) {
    if("number" == typeof a) {
        // 'a' is array length
        this.m_ints = new Array(a);
        for(var i=0; i<a; i++) this.m_ints[i]=0;
    } else if(a.constructor == Array) {
        // 'a' is array
        this.m_ints = a.slice(0);
    } else if(a.constructor == BigInteger && "number" == typeof b) {
        // 'a' is BigInteger, 'b' is minIntLen
        if(a.equals(BigInteger.ZERO)) {
            this.m_ints = new Array(1);
            this.m_ints[0] = 0;
            return;
        }
        
        var minIntLen = b;
        
        var barr = a.toByteArray();
        var barrLen = barr.length;
        var barrStart = 0;
        if(barr[0] == 0) {
            barrLen--;
            barrStart = 1;
        }
        var intLen = (barrLen + 3) >> 2; // division by 4
        this.m_ints = new Array((intLen < minIntLen) ? minIntLen : intLen);
        for(var i=0; i<this.m_ints.length; i++) this.m_ints[i]=0;
        
        var iarrJ = intLen - 1;
        var rem = barrLen % 4 + barrStart;
        var temp = 0;
        var barrI = barrStart;
        if(barrStart < rem) {
            for (; barrI < rem; barrI++) {
                temp <<= 8;
                var barrBarrI = barr[barrI];
                if(barrBarrI < 0) {
                    barrBarrI += 256;
                }
                temp |= barrBarrI;
            }
            this.m_ints[iarrJ--] = temp;
        }
        
        for (; iarrJ >= 0; iarrJ--) {
            temp = 0;
            for (var i = 0; i < 4; i++)
            {
                temp <<= 8;
                var barrBarrI = barr[barrI++];
                if (barrBarrI < 0) {
                    barrBarrI += 256;
                }
                temp |= barrBarrI;
            }
            this.m_ints[iarrJ] = temp;
        }
    }
}

function iaIsZero() {
    return this.m_ints.length == 0 || (this.m_ints[0] == 0 && this.getUsedLength() == 0);
}

function iaGetUsedLength() {
    var highestIntPos = this.m_ints.length;

    if(highestIntPos < 1) {
        return 0;
    }
    
    if(this.m_ints[0] != 0) {
        do {
            highestIntPos = highestIntPos - 1;
        } while(this.m_ints[highestIntPos] == 0);
        return highestIntPos + 1;
    }
    
    do {
        highestIntPos = highestIntPos - 1;
        if(this.m_ints[highestIntPos] != 0)
            return highestIntPos + 1;
    }
    while(highestIntPos > 0);

    return 0;
}

function iaBitLength() {
    var intLen = this.getUsedLength();
    if(intLen == 0) {
        return 0;
    }

    var last = intLen - 1;
    var highest = this.m_ints[last];
    var bits = (last << 5) + 1;
    
    if((highest & 0xffff0000) != 0) {
        if((highest & 0xff000000) != 0) {
            bits += 24;
            highest >>>= 24;
        }
        else {
            bits += 16;
            highest >>>= 16;
        }
    }
    else if(highest > 0x000000ff) {
        bits += 8;
        highest >>>= 8;
    }
    
    while(highest != 1) {
        ++bits;
        highest >>>= 1;
    }
    
    return bits;
}

function iaResizedInts(newLen) {
    var oldLen = this.m_ints.length;
    var copyLen = oldLen < newLen ? oldLen : newLen;
    var newInts = this.m_ints.slice(0,copyLen);
    return newInts;
}

function iaToByteArray() {
    var usedLen = this.getUsedLength();
    if(usedLen == 0) {
        return BigInteger.ZERO;
    }

    var highestInt = this.m_ints[usedLen - 1];
    var temp = new Array(4);
    var barrI = 0;
    var trailingZeroBytesDone = false;
    for(var j = 3; j >= 0; j--) {
        var thisByte = (highestInt >>> (8 * j)) & 0xFF;
        if(trailingZeroBytesDone || (thisByte != 0)) {
            trailingZeroBytesDone = true;
            temp[barrI++] = thisByte;
        }
    }

    var barrLen = 4 * (usedLen - 1) + barrI;
    var barr = new Array(barrLen);
    for(var j = 0; j < barrI; j++) {
        barr[j] = temp[j];
    }

    for(var iarrJ = usedLen - 2; iarrJ >= 0; iarrJ--) {
        for(var j = 3; j >= 0; j--) {
            barr[barrI++] = (this.m_ints[iarrJ] >>> (8 * j)) & 0xFF;
        }
    }
    
    return barr;
}

function iaToBigInteger() {
    return new BigInteger(prepareByteArray(this.toByteArray()));
}

function iaShiftLeft(n) {
    var usedLen = this.getUsedLength();
    if("number" == typeof n) {
        if(usedLen == 0 || n == 0) {
            return this;
        }
        
        if(n > 31) {
            throw "shiftLeft() for max 31 bits "+ ", " + n + "bit shift is not possible";
            //return null;
        }
        
        var newInts = new Array(usedLen+1);
        
        var nm32 = 32 - n;
        newInts[0] = this.m_ints[0] << n;
        for(var i = 1; i < usedLen; i++) {
            newInts[i] = (this.m_ints[i] << n) | (this.m_ints[i - 1] >>> nm32);
        }
        newInts[usedLen] = this.m_ints[usedLen - 1] >>> nm32;

        return new IntArray(newInts);
    }
    else {
        if(usedLen == 0) {
            return;
        }
        if(this.m_ints[usedLen - 1] < 0) {
            usedLen++;
            if (usedLen > this.m_ints.length) {
                this.m_ints = this.resizedInts(this.m_ints.length + 1);
            }
        }

        var carry = false;
        for(var i = 0; i < usedLen; i++) {
            var nextCarry = (this.m_ints[i] < 0);
            this.m_ints[i] <<= 1;
            if(carry) {
                this.m_ints[i] |= 1;
            }
            carry = nextCarry;
        }
    }
}

function iaAddShifted(other, shift) {
    var usedLenOther = other.getUsedLength();
    var newMinUsedLen = usedLenOther + shift;
    if(newMinUsedLen > this.m_ints.length) {
        this.m_ints = this.resizedInts(newMinUsedLen);
    }

    for(var i = 0; i < usedLenOther; i++) {
        this.m_ints[i + shift] ^= other.m_ints[i];
    }
}

function iaGetLength() {
    return this.m_ints.length;
}

function iaTestBit(n) {
    var theInt = n >> 5;
    var theBit = n & 0x1F;
    var tester = 1 << theBit;
    return ((this.m_ints[theInt] & tester) != 0);
}

function iaFlipBit(n) {
    var theInt = n >> 5;
    var theBit = n & 0x1F;
    var flipper = 1 << theBit;
    this.m_ints[theInt] ^= flipper;
}

function iaSetBit(n) {
    var theInt = n >> 5;
    var theBit = n & 0x1F;
    var setter = 1 << theBit;
    this.m_ints[theInt] |= setter;
}

function iaMultiply(other, m) {
    var t = (m + 31) >> 5;
    if(this.m_ints.length < t) {
        this.m_ints = resizedInts(t);
    }

    var b = new IntArray(other.resizedInts(other.getLength() + 1));
    var c = new IntArray((m + m + 31) >> 5);
    
    var testBit = 1;
    for(var k = 0; k < 32; k++) {
        for(var j = 0; j < t; j++) {
            if((this.m_ints[j] & testBit) != 0) {
                c.addShifted(b, j);
            }
        }
        testBit <<= 1;
        b.shiftLeft();
    }
    return c;
}

function iaReduce(m, redPol) {
    for(var i = m + m - 2; i >= m; i--) {
        if(this.testBit(i)) {
            var bit = i - m;
            this.flipBit(bit);
            this.flipBit(i);
            var l = redPol.length;
            while (--l >= 0) {
                this.flipBit(redPol[l] + bit);
            }
        }
    }
    this.m_ints = this.resizedInts((m + 31) >> 5);
}

function iaSquare(m) {
    var table = [ 0x0, 0x1, 0x4, 0x5, 0x10, 0x11, 0x14, 0x15, 0x40,
        0x41, 0x44, 0x45, 0x50, 0x51, 0x54, 0x55 ];

    var t = (m + 31) >> 5;
    if(this.m_ints.length < t) {
        this.m_ints = this.resizedInts(t);
    }

    var c = new IntArray(t + t);
    
    for(var i = 0; i < t; i++) {
        var v0 = 0;
        for(var j = 0; j < 4; j++) {
            v0 = v0 >>> 8;
            var u = (this.m_ints[i] >>> (j * 4)) & 0xF;
            var w = table[u] << 24;
            v0 |= w;
        }
        c.m_ints[i + i] = v0;

        v0 = 0;
        var upper = this.m_ints[i] >>> 16;
        for(var j = 0; j < 4; j++) {
            v0 = v0 >>> 8;
            var u = (upper >>> (j * 4)) & 0xF;
            var w = table[u] << 24;
            v0 |= w;
        }
        c.m_ints[i + i + 1] = v0;
    }
    return c;
}

function iaEquals(other)
{
    var usedLen = this.getUsedLength();
    if(other.getUsedLength() != usedLen) {
        return false;
    }
    for(var i = 0; i < usedLen; i++) {
        if (this.m_ints[i] != other.m_ints[i]) {
            return false;
        }
    }
    return true;
}

function iaHashCode() {
    var usedLen = this.getUsedLength();
    var hash = 1;
    for(var i = 0; i < usedLen; i++) {
        hash = hash * 31 + this.m_ints[i];
    }
    return hash;
}

function iaClone() {
    return new IntArray(this.m_ints);
}

function iaToString() {
    var usedLen = this.getUsedLength();
    if(usedLen == 0) {
        return "0";
    }
    
    var s="";
    
    for(var iarrJ = usedLen - 2; iarrJ >= 0; iarrJ--) {
        var hexString = this.m_ints[iarrJ].toString(2);
        
        for(var i = hexString.length; i < 8; i++) {
            hexString = "0" + hexString;
        }
        s += hexString;
    }
    return s;
}

IntArray.prototype.isZero = iaIsZero;
IntArray.prototype.getUsedLength = iaGetUsedLength;
IntArray.prototype.bitLength = iaBitLength;
IntArray.prototype.resizedInts = iaResizedInts;
IntArray.prototype.toByteArray = iaToByteArray;
IntArray.prototype.toBigInteger = iaToBigInteger;
IntArray.prototype.shiftLeft = iaShiftLeft;
IntArray.prototype.addShifted = iaAddShifted;
IntArray.prototype.getLength = iaGetLength;
IntArray.prototype.testBit = iaTestBit;
IntArray.prototype.flipBit = iaFlipBit;
IntArray.prototype.setBit = iaSetBit;
IntArray.prototype.multiply = iaMultiply;
IntArray.prototype.reduce = iaReduce;
IntArray.prototype.square = iaSquare;
IntArray.prototype.equals = iaEquals;
IntArray.prototype.hashCode = iaHashCode;
IntArray.prototype.clone = iaClone;
IntArray.prototype.toString = iaToString;

// ----------------
// ECFieldElementF2m

// constructor
function ECFieldElementF2m(m,a,b,c,d) {
    this.t = (m+31) >> 5;
    
    var k1,k2,k3;
    var x;
    
    if("number" == typeof a && b.constructor == BigInteger) {
        k1 = a;
        k2 = 0;
        k3 = 0;
        x = b;
    }
    else if("number" == typeof a && "number" == typeof b && "number" == typeof b) {
        k1 = a;
        k2 = b;
        k3 = c;
        x = d;
    }
    else {
        throw "ECFieldElementF2m: invalid parameters!";
    }
    
    if(x.constructor == BigInteger) {
        this.x = new IntArray(x,this.t);
        
        if((k2 == 0) && (k3 == 0)) {
            this.representation = ECFieldElementF2m.TPB;
        }
        else {
            if (k2 >= k3) {
                throw "ECFieldElementF2m: k2 must be smaller than k3";
            }
            if (k2 <= 0) {
                throw "ECFieldElementF2m: k2 must be larger than 0";
            }
            this.representation = ECFieldElementF2m.PPB;
        }

        if(x.signum() < 0) {
            throw "ECFieldElementF2m: x value cannot be negative";
        }
        
        this.m = m;
        this.k1 = k1;
        this.k2 = k2;
        this.k3 = k3;
    }
    else if(x.constructor == IntArray) {
        this.x = x.clone();
        this.m = m;
        this.k1 = k1;
        this.k2 = k2;
        this.k3 = k3;

        if ((k2 == 0) && (k3 == 0))
        {
            this.representation = ECFieldElementF2m.TPB;
        }
        else
        {
            this.representation = ECFieldElementF2m.PPB;
        }
    }
    else {
        throw "ECFieldElementF2m: x has unknown type!";
    }
}

function fmtarr(x) {
    var s="";
    s = s + x.length.toString() + ": {" + x + "}";
    
    return s;
}

function feF2mEquals(b) {
    
    if(b == this) return true;
    if(b.constructor != ECFieldElementF2m) return false;
    return ((this.m == b.m) && (this.k1 == b.k1) && (this.k2 == b.k2)
        && (this.k3 == b.k3)
        && (this.representation == b.representation)
        && (this.x.equals(b.x)));
}

function feF2mToBigInteger() {
    return this.x.toBigInteger();
}

function feF2mToByteArray() {
    return this.x.toByteArray();
}

function feF2mInvert() {
    var uz = this.x.clone();
    var vz = new IntArray(this.t);
    vz.setBit(this.m);
    vz.setBit(0);
    vz.setBit(this.k1);
    if(this.representation == ECFieldElementF2m.PPB) {
        vz.setBit(this.k2);
        vz.setBit(this.k3);
    }
    
    var g1z = new IntArray(this.t);
    g1z.setBit(0);
    var g2z = new IntArray(this.t);
    
    while (!uz.isZero()) {
        var j = uz.bitLength() - vz.bitLength();
        
        if(j < 0) {
            var uzCopy = uz;
            uz = vz;
            vz = uzCopy;

            var g1zCopy = g1z;
            g1z = g2z;
            g2z = g1zCopy;

            j = -j;
        }
        
        var jInt = j >> 5;
        var jBit = j & 0x1F;
        
        var vzShift = vz.shiftLeft(jBit);
        uz.addShifted(vzShift, jInt);
        
        var g2zShift = g2z.shiftLeft(jBit);
        g1z.addShifted(g2zShift, jInt);
    }
    return new ECFieldElementF2m(this.m, this.k1, this.k2, this.k3, g2z);
}

function feF2mNegate() {
    return new ECFieldElementF2m(this.m, this.k1, this.k2, this.k3, this.x);
}

function feF2mAdd(b) {
    var iarrClone = this.x.clone();
    iarrClone.addShifted(b.x, 0);
    return new ECFieldElementF2m(this.m, this.k1, this.k2, this.k3, iarrClone);
}

function feF2mSubtract(b) {
    return this.add(b);
}

function feF2mMultiply(b) {
    var mult = this.x.multiply(b.x, this.m);
    var redPol = [this.k1,this.k2,this.k3];
    
    mult.reduce(this.m, redPol);
    return new ECFieldElementF2m(this.m, this.k1, this.k2, this.k3, mult);
}

function feF2mSquare() {
    var squared = this.x.square(this.m);
    var redPol = [this.k1,this.k2,this.k3];
    squared.reduce(this.m, redPol);
    return new ECFieldElementF2m(this.m, this.k1, this.k2, this.k3, squared);
}

function feF2mDivide(b) {
    var bInv = b.invert();
    return this.multiply(bInv);
}

ECFieldElementF2m.prototype.equals = feF2mEquals;
ECFieldElementF2m.prototype.toByteArray = feF2mToByteArray;
ECFieldElementF2m.prototype.toBigInteger = feF2mToBigInteger;
ECFieldElementF2m.prototype.invert = feF2mInvert;
ECFieldElementF2m.prototype.negate = feF2mNegate;
ECFieldElementF2m.prototype.add = feF2mAdd;
ECFieldElementF2m.prototype.subtract = feF2mSubtract;
ECFieldElementF2m.prototype.multiply = feF2mMultiply;
ECFieldElementF2m.prototype.square = feF2mSquare;
ECFieldElementF2m.prototype.divide = feF2mDivide;

ECFieldElementF2m.GNB = 1;
ECFieldElementF2m.TPB = 2;
ECFieldElementF2m.PPB = 3;

// ----------------
// ECPointF2m

// constructor
function ECPointF2m(curve,x,y) {
    this.curve = curve;
    this.x = x;
    this.y = y;
    //TODO: compression flag
}

function pointF2mGetEncoded(withCompression) {
    var PO;

    if(this.isInfinity()) {
        PO = new Array(1);
        P[0] = 0;
    }
    else {
        var X = this.getX().toByteArray();
        if(withCompression) {
            var qLength = X.length;
            PO = new Array(qLength + 1);

            PO[0] = 0x02;
            if(!(this.getX().toBigInteger().equals(BigInteger.ZERO)))
            {
                if(this.getY().multiply(this.getX().invert())
                        .toBigInteger().testBit(0))
                {
                    PO[0] = 0x03;
                }
            }
            
            for(var i=0; i<qLength; i++) {
                PO[1+i] = X[i];
            }
        }
        else {
            var Y = this.getY().toByteArray();

            var qLength = X.length > Y.length ? X.length : Y.length;
            PO = new Array(qLength*2+1);

            PO[0] = 0x04;
            // copy X-part
            var offs = 1 + (qLength-X.length);
            for(var i=1; i<offs; i++) {
                PO[i]=0;
            }
            for(var i=0; i<X.length; i++) {
                PO[offs+i] = X[i];
            }
            // copy Y-part
            offs = 1 + qLength + (qLength-Y.length);
            for(var i=1+qLength; i<offs; i++) {
                PO[i]=0;
            }
            for(var i=0; i<Y.length; i++) {
                PO[offs+i] = Y[i];
            }
        }
    }
    return PO;
}

function pointF2mGetX() {
    return this.x;
}

function pointF2mGetY() {
    return this.y;
}

function pointF2mEquals(b) {
    if(b == this) return true;
    if(this.isInfinity()) return b.isInfinity();
    if(b.isInfinity()) return this.isInfinity();
    return (this.x.equals(b.x) && this.y.equals(b.y));
}

function pointF2mIsInfinity() {
    return((this.x == null) && (this.y == null));
}

function pointF2mNegate() {
    return new ECPointF2m(this.curve, this.getX(), this.getY().add(this.getX()));
}

function pointF2mAdd(b) {
    if(this.isInfinity()) return b;
    if(b.isInfinity()) return this;
    
    var x2 = b.getX();
    var y2 = b.getY();
    
    if(this.x.equals(x2)) {
        if(this.y.equals(y2)) {
            return this.twice();
        }
        return this.curve.getInfinity();
    }

    var lambda = (this.y.add(y2)).divide(this.x.add(x2));
    var x3 = lambda.square().add(lambda).add(this.x).add(x2).add(this.curve.getA());
    var y3 = lambda.multiply(this.x.add(x3)).add(x3).add(this.y);
    
    return new ECPointF2m(this.curve, x3, y3);
}

function pointF2mTwice() {
    if(this.isInfinity()) {
        return this;
    }

    if(this.x.toBigInteger().signum() == 0) {
        return this.curve.getInfinity();
    }

    var lambda = this.x.add(this.y.divide(this.x));
    var x3 = lambda.square().add(lambda).add(this.curve.getA());
    var ONE = this.curve.fromBigInteger(BigInteger.ONE);
    var y3 = this.x.square().add(x3.multiply(lambda.add(ONE)));

    return new ECPointF2m(this.curve, x3, y3);
}

function pointF2mMultiply(k) {
    if(this.isInfinity()) return this;
    if(k.signum() == 0) return this.curve.getInfinity();

    var e = k;
    var h = e.multiply(new BigInteger("3"));

    var neg = this.negate();
    var R = this;

    var i;
    for(i = h.bitLength() - 2; i > 0; --i) {
        R = R.twice();

        var hBit = h.testBit(i);
        var eBit = e.testBit(i);

        if(hBit != eBit) {
            R = R.add(hBit ? this : neg);
        }
    }

    return R;
}

// Compute this*j + x*k (simultaneous multiplication)
function pointF2mMultiplyTwo(j,x,k) {
  var i;
  if(j.bitLength() > k.bitLength())
    i = j.bitLength() - 1;
  else
    i = k.bitLength() - 1;

  var R = this.curve.getInfinity();
  var both = this.add(x);
  while(i >= 0) {
    R = R.twice();
    if(j.testBit(i)) {
      if(k.testBit(i)) {
        R = R.add(both);
      }
      else {
        R = R.add(this);
      }
    }
    else {
      if(k.testBit(i)) {
        R = R.add(x);
      }
    }
    --i;
  }

  return R;
}

ECPointF2m.prototype.getEncoded = pointF2mGetEncoded;
ECPointF2m.prototype.getX = pointF2mGetX;
ECPointF2m.prototype.getY = pointF2mGetY;
ECPointF2m.prototype.equals = pointF2mEquals;
ECPointF2m.prototype.isInfinity = pointF2mIsInfinity;
ECPointF2m.prototype.negate = pointF2mNegate;
ECPointF2m.prototype.add = pointF2mAdd;
ECPointF2m.prototype.twice = pointF2mTwice;
ECPointF2m.prototype.multiply = pointF2mMultiply;
ECPointF2m.prototype.multiplyTwo = pointF2mMultiplyTwo;

// ----------------
// ECCurveF2m

// constructor
function ECCurveF2m(m,k,a,b,c,d,e,f) {
    if("number" != typeof m) {
        throw "ECCurveF2m: invalid typeof m!";
    }
    this.m = m;
    var k1,k2,k3;
    if(a.constructor == BigInteger && b.constructor == BigInteger) {
        this.k1 = k;
        this.k2 = 0;
        this.k3 = 0;
        this.a = this.fromBigInteger(a);
        this.b = this.fromBigInteger(b);
        this.n = c;
        this.h = d;
    }
    else if("number" == typeof a && "number" == typeof b) {
        this.k1 = k;
        this.k2 = a;
        this.k3 = b;
        this.a = this.fromBigInteger(c);
        this.b = this.fromBigInteger(d);
        this.n = e;
        this.h = f;
    } else {
        throw "ECCurveF2m: parameters!";
    }
    
    if(this.k1 == 0) {
        throw "ECCurveF2m: k1 must be > 0";
    }

    if(this.k2 == 0) {
        if(this.k3 != 0) {
            throw "ECCurveF2m: k3 must be 0 if k2 == 0";
        }
    }
    else {
        if(this.k2 <= this.k1) {
            throw "ECCurveF2m: k2 must be > k1";
        }

        if(this.k3 <= this.k2) {
            throw "ECCurveF2m: k3 must be > k2";
        }
    }
    
    this.infinity = new ECPointF2m(this, null, null);
}

function curveF2mGetM() {
    return this.m;
}

function curveF2mGetA() {
    return this.a;
}

function curveF2mGetB() {
    return this.b;
}

function curveF2mEquals(other) {
    if(other == this) return true;
    return(this.m == other.m) && (this.k1 == other.k1) && (this.k2 == other.k2) && (this.k3 == other.k3) && a.equals(other.a) && b.equals(other.b);
}

function curveF2mGetInfinity() {
    return this.infinity;
}

function curveF2mCreatePoint(x,y) {
    return new ECPointF2m(this, this.fromBigInteger(x), this.fromBigInteger(y));
}

function curveF2mFromBigInteger(x) {
    return new ECFieldElementF2m(this.m, this.k1, this.k2, this.k3, x);
}

// ready here

function curveF2mSolveQuadradicEquation(beta) {
    var zeroElement = new ECFieldElementF2m(this.m, this.k1, this.k2, this.k3, BigInteger.ZERO);

    if(beta.toBigInteger().equals(BigInteger.ZERO)) {
        return zeroElement;
    }

    var z = null;
    var gamma = zeroElement;

    var rand = new SecureRandom(); // drugogo prosto net :)
    do {
        var t = new ECFieldElementF2m(this.m, this.k1, this.k2, this.k3, new BigInteger(this.m, rand));
        z = zeroElement;
        var w = beta;
        for(var i = 1; i <= this.m - 1; i++) {
            var w2 = w.square();
            z = z.square().add(w2.multiply(t));
            w = w2.add(beta);
        }
        if(!w.toBigInteger().equals(BigInteger.ZERO)) {
            return null;
        }
        gamma = z.square().add(z);
    }
    while(gamma.toBigInteger().equals(BigInteger.ZERO));

    return z;
}

function curveF2mDecompressPoint(xEnc, ypBit) {
    var xp = new ECFieldElementF2m(this.m, this.k1, this.k2, this.k3, new BigInteger(prepareByteArray(xEnc)));
    var yp = null;
    if(xp.toBigInteger().equals(BigInteger.ZERO)) {
        yp = this.b;
        for(var i = 0; i < m - 1; i++) {
            yp = yp.square();
        }
    }
    else {
        var beta = xp.add(this.a).add(this.b.multiply(xp.square().invert()));
        var z = this.solveQuadradicEquation(beta);
        if(z == null) {
            throw ("Invalid point compression");
        }
        var zBit = 0;
        if(z.toBigInteger().testBit(0)) {
            zBit = 1;
        }
        if(zBit != ypBit) {
            z = z.add(new ECFieldElementF2m(this.m, this.k1, this.k2,
                    this.k3, BigInteger.ONE));
        }
        yp = xp.multiply(z);
    }
    
    return new ECPointF2m(this, xp, yp);
}

// for now, work with hex strings because they're easier in JS
function curveF2mDecodePointHex(s) {
    switch(parseInt(s.substr(0,2), 16)) { // first byte
    case 0:
    return this.infinity;
    case 2:
    case 3:
    // point compression not supported yet
    return null;
    case 4:
    case 6:
    case 7:
    var len = (s.length - 2) / 2;
    var xHex = s.substr(2, len);
    var yHex = s.substr(len+2, len);

    return new ECPointF2m(this,
                this.fromBigInteger(new BigInteger(xHex, 16)),
                this.fromBigInteger(new BigInteger(yHex, 16)));

    default: // unsupported
    return null;
    }
}

function curveF2mDecodePoint(b) {
    //return this.decodePointHex(digest2str(b));
    switch(b[0]) {
    case 0:
        return this.infinity;
    case 2:
    case 3:
        var bX = b.slice(1);
        if(b[0] == 0x02) {
            return this.decompressPoint(bX, 0);
        }
        else {
            return this.decompressPoint(bX, 1);
        }
    case 4:
    case 6:
    case 7:
        var qLength = (b.length - 1) / 2;
        var bX = b.slice(1,1+qLength);
        var bY = b.slice(1+qLength,1+2*qLength);
        
        //var xHex = digest2str(bX);
        //var yHex = digest2str(bY);
        
        /*return new ECPointF2m(this,
                this.fromBigInteger(new BigInteger(xHex, 16)),
                this.fromBigInteger(new BigInteger(yHex, 16)));*/
        
        return new ECPointF2m(this,
			     this.fromBigInteger(new BigInteger(prepareByteArray(bX))),
			     this.fromBigInteger(new BigInteger(prepareByteArray(bY))), null);
    default: // unsupported
        return null;
    }
}

ECCurveF2m.prototype.getM = curveF2mGetM;
ECCurveF2m.prototype.getA = curveF2mGetA;
ECCurveF2m.prototype.getB = curveF2mGetB;
ECCurveF2m.prototype.equals = curveF2mEquals;
ECCurveF2m.prototype.getInfinity = curveF2mGetInfinity;
ECCurveF2m.prototype.fromBigInteger = curveF2mFromBigInteger;
ECCurveF2m.prototype.createPoint = curveF2mCreatePoint;
ECCurveF2m.prototype.solveQuadradicEquation = curveF2mSolveQuadradicEquation;
ECCurveF2m.prototype.decompressPoint = curveF2mDecompressPoint;
ECCurveF2m.prototype.decodePointHex = curveF2mDecodePointHex;
ECCurveF2m.prototype.decodePoint = curveF2mDecodePoint;
