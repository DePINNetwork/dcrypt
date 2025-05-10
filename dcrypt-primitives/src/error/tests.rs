#[cfg(test)]
mod tests {
    use super::*;
    use dcrypt_core::error::{Error as CoreError, SecureErrorHandling};

    #[test]
    fn test_error_conversion() {
        // Parameter error
        let err = Error::Parameter {
            name: "test",
            reason: "invalid value",
        };
        let core_err = CoreError::from(err);
        
        match core_err {
            CoreError::InvalidParameter { context, .. } => {
                assert_eq!(context, "test");
            }
            _ => panic!("Expected InvalidParameter error"),
        }
        
        // Length error
        let err = Error::Length {
            context: "buffer",
            expected: 32,
            actual: 16,
        };
        let core_err = CoreError::from(err);
        
        match core_err {
            CoreError::InvalidLength { context, expected, actual } => {
                assert_eq!(context, "buffer");
                assert_eq!(expected, 32);
                assert_eq!(actual, 16);
            }
            _ => panic!("Expected InvalidLength error"),
        }
    }
    
    #[test]
    fn test_validation_functions() {
        // Parameter validation
        assert!(validate::parameter(true, "test", "should pass").is_ok());
        let err = validate::parameter(false, "test", "should fail").unwrap_err();
        
        match err {
            Error::Parameter { name, reason } => {
                assert_eq!(name, "test");
                assert_eq!(reason, "should fail");
            }
            _ => panic!("Expected Parameter error"),
        }
        
        // Length validation
        assert!(validate::length("buffer", 32, 32).is_ok());
        let err = validate::length("buffer", 16, 32).unwrap_err();
        
        match err {
            Error::Length { context, expected, actual } => {
                assert_eq!(context, "buffer");
                assert_eq!(expected, 32);
                assert_eq!(actual, 16);
            }
            _ => panic!("Expected Length error"),
        }
    }
    
    #[test]
    fn test_secure_error_handling() {
        let result: Result<()> = validate::authentication(false, "test");
        
        // Test secure unwrapping
        let dummy_value = 42;
        let returned = result.secure_unwrap(dummy_value, || {
            Error::Authentication { algorithm: "test" }
        });
        
        assert_eq!(returned, dummy_value);
    }
}