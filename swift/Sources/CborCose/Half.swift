/// IEEE 754 half-precision (binary16) helpers for CBOR preferred float serialization.
enum Half {

    /// Half bits -> double (exact; subnormals, ±0, ±inf, NaN).
    static func toDouble(_ h: UInt16) -> Double {
        let neg = (h & 0x8000) != 0
        let exp = Int((h >> 10) & 0x1F)
        let mant = Int(h & 0x3FF)
        let mag: Double
        switch exp {
        case 0:
            mag = Double(sign: .plus, exponent: -24, significand: Double(mant))
        case 0x1F:
            mag = mant == 0 ? .infinity : .nan
        default:
            mag = Double(sign: .plus, exponent: exp - 25, significand: Double(0x400 | mant))
        }
        return neg ? -mag : mag
    }

    /// Returns the half bits if `d` is exactly representable as binary16, else nil.
    /// NaN is excluded (the encoder canonicalizes NaN to 0x7e00 separately).
    static func exactBits(of d: Double) -> UInt16? {
        if d.isNaN { return nil }
        let bits = d.bitPattern
        let sign = UInt16((bits >> 48) & 0x8000)
        if d.isInfinite { return sign | 0x7C00 }
        if d == 0 { return bits == 0 ? 0x0000 : 0x8000 }
        let exp = Int((bits >> 52) & 0x7FF) - 1023
        let mant = bits & 0xF_FFFF_FFFF_FFFF
        if exp >= -14 && exp <= 15 {
            // normal half: needs a 10-bit mantissa
            if (mant & ((1 << 42) - 1)) != 0 { return nil }
            return sign | (UInt16(exp + 15) << 10) | UInt16(mant >> 42)
        }
        if exp >= -24 && exp <= -15 {
            // subnormal half: d = ±k * 2^-24, 1 <= k <= 1023
            let shift = UInt64(52 - (exp + 24))
            let full: UInt64 = (1 << 52) | mant
            if (full & ((1 << shift) - 1)) != 0 { return nil }
            let k = full >> shift
            if (1...0x3FF).contains(k) { return sign | UInt16(k) }
        }
        return nil
    }
}
