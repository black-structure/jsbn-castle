// Originally written by Tom Wu http://www-cs-students.stanford.edu/~tjw/jsbn/
// Copyright (c) 2005  Tom Wu
// All Rights Reserved.
// See "LICENSE.old" for details.

function BigIntegers() {}

BigIntegers.createRandomInRange = function(min,max,random) {
    var MAX_ITERATIONS = 1000;
    var cmp = min.compareTo(max);
    if(cmp >= 0) {
        if(cmp > 0) {
            throw "'min' may not be greater than 'max'";
        }
        return min;
    }

    if(min.bitLength() > max.bitLength() / 2) {
        return BigIntegers.createRandomInRange(BigInteger.ZERO, max.subtract(min), random).add(min);
    }

    for(var i = 0; i < MAX_ITERATIONS; ++i) {
        var x = new BigInteger(max.bitLength(), random);
        if(x.compareTo(min) >= 0 && x.compareTo(max) <= 0) {
            return x;
        }
    }
    
    return new BigInteger(max.subtract(min).bitLength() - 1, random).add(min);
}
