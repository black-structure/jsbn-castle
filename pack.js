
function PackbigEndianToInt(bs, off)
{
    var n = bs[  off] << 24;
    n |= (bs[++off] & 0xff) << 16;
    n |= (bs[++off] & 0xff) << 8;
    n |= (bs[++off] & 0xff);
    return n;
}

function PackintToBigEndian(n, bs, off)
{
    bs[  off] = (n >>> 24) & 0xFF;
    bs[++off] = (n >>> 16) & 0xFF;
    bs[++off] = (n >>>  8) & 0xFF;
    bs[++off] = (n       ) & 0xFF;
}

function PackbigEndianToLong(bs, off) {
    var hi = PackbigEndianToInt(bs, off);
    var lo = PackbigEndianToInt(bs, off + 4);
    return ((hi & 0xffffffff) << 32) | (lo & 0xffffffff);
}

function PacklongToBigEndian(n, bs, off) {
    PackintToBigEndian((n >>> 32), bs, off);
    PackintToBigEndian((n & 0xffffffff), bs, off + 4);
}

function PacklittleEndianToInt(bs, off) {
    var n = bs[  off];
    n |= (bs[++off] & 0xff) << 8;
    n |= (bs[++off] & 0xff) << 16;
    n |= (bs[++off] & 0xff) << 24;
    return n;
}

function PackintToLittleEndian(n, bs, off) {
    bs[  off] = (n       ) & 0xFF;
    bs[++off] = (n >>>  8) & 0xFF;
    bs[++off] = (n >>> 16) & 0xFF;
    bs[++off] = (n >>> 24) & 0xFF;
}

function PacklittleEndianToLong(bs, off) {
    var lo = PacklittleEndianToInt(bs, off);
    var hi = PacklittleEndianToInt(bs, off + 4);
    return ((hi & 0xffffffff) << 32) | (lo & 0xffffffff);
}

function PacklongToLittleEndian(n, bs, off) {
    PackintToLittleEndian((n & 0xffffffff), bs, off);
    PackintToLittleEndian((n >>> 32), bs, off + 4);
}