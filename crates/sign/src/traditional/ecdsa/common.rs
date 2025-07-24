//! Common utilities for ECDSA implementations

use dcrypt_api::{Result as ApiResult, error::Error as ApiError};

/// ECDSA signature components (r, s)
#[derive(Clone, Debug)]
pub struct SignatureComponents {
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}

impl SignatureComponents {
    /// Serialize signature to DER format
    pub fn to_der(&self) -> Vec<u8> {
        // DER encoding: SEQUENCE { INTEGER r, INTEGER s }
        let mut der = Vec::new();
        
        // Add SEQUENCE tag
        der.push(0x30);
        
        // Calculate and add length (placeholder, will update)
        let len_pos = der.len();
        der.push(0x00);
        
        // Encode r
        der.push(0x02); // INTEGER tag
        let r_bytes = self.encode_integer(&self.r);
        der.push(r_bytes.len() as u8);
        der.extend_from_slice(&r_bytes);
        
        // Encode s
        der.push(0x02); // INTEGER tag
        let s_bytes = self.encode_integer(&self.s);
        der.push(s_bytes.len() as u8);
        der.extend_from_slice(&s_bytes);
        
        // Update sequence length
        let total_len = der.len() - len_pos - 1;
        der[len_pos] = total_len as u8;
        
        der
    }
    
    /// Parse signature from DER format
    pub fn from_der(der: &[u8]) -> ApiResult<Self> {
        if der.len() < 8 {
            return Err(ApiError::InvalidSignature {
                context: "ECDSA DER parsing",
                #[cfg(feature = "std")]
                message: "DER signature too short".to_string(),
            });
        }
        
        // Check SEQUENCE tag
        if der[0] != 0x30 {
            return Err(ApiError::InvalidSignature {
                context: "ECDSA DER parsing",
                #[cfg(feature = "std")]
                message: "Invalid DER SEQUENCE tag".to_string(),
            });
        }
        
        let mut pos = 2; // Skip tag and length
        
        // Parse r
        if der[pos] != 0x02 {
            return Err(ApiError::InvalidSignature {
                context: "ECDSA DER parsing",
                #[cfg(feature = "std")]
                message: "Invalid DER INTEGER tag for r".to_string(),
            });
        }
        pos += 1;
        let r_len = der[pos] as usize;
        pos += 1;
        let r = der[pos..pos + r_len].to_vec();
        pos += r_len;
        
        // Parse s
        if der[pos] != 0x02 {
            return Err(ApiError::InvalidSignature {
                context: "ECDSA DER parsing",
                #[cfg(feature = "std")]
                message: "Invalid DER INTEGER tag for s".to_string(),
            });
        }
        pos += 1;
        let s_len = der[pos] as usize;
        pos += 1;
        let s = der[pos..pos + s_len].to_vec();
        
        Ok(SignatureComponents {
            r: Self::decode_integer(&r),
            s: Self::decode_integer(&s),
        })
    }
    
    /// Encode integer for DER (add leading zero if high bit set)
    fn encode_integer(&self, bytes: &[u8]) -> Vec<u8> {
        if bytes.is_empty() || bytes[0] & 0x80 == 0 {
            bytes.to_vec()
        } else {
            // Add leading zero byte
            let mut result = vec![0x00];
            result.extend_from_slice(bytes);
            result
        }
    }
    
    /// Decode integer from DER (remove leading zeros)
    fn decode_integer(bytes: &[u8]) -> Vec<u8> {
        let mut result = bytes.to_vec();
        while result.len() > 1 && result[0] == 0x00 {
            result.remove(0);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_der_encoding() {
        let sig = SignatureComponents {
            r: vec![0x01, 0x23, 0x45, 0x67],
            s: vec![0x89, 0xAB, 0xCD, 0xEF],
        };
        
        let der = sig.to_der();
        let parsed = SignatureComponents::from_der(&der).unwrap();
        
        assert_eq!(sig.r, parsed.r);
        assert_eq!(sig.s, parsed.s);
    }
    
    #[test]
    fn test_der_with_high_bit() {
        // Test encoding when high bit is set (requires leading zero)
        let sig = SignatureComponents {
            r: vec![0xFF, 0x23, 0x45, 0x67],
            s: vec![0x79, 0xAB, 0xCD, 0xEF],
        };
        
        let der = sig.to_der();
        
        // Check that r has leading zero in DER
        assert_eq!(der[3], 5); // r length should be 5 (extra zero byte)
        assert_eq!(der[4], 0x00); // leading zero
        assert_eq!(der[5], 0xFF); // original first byte
        
        // Parse back and verify
        let parsed = SignatureComponents::from_der(&der).unwrap();
        assert_eq!(sig.r, parsed.r);
        assert_eq!(sig.s, parsed.s);
    }
}