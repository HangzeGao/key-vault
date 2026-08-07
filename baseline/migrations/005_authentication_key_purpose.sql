ALTER TABLE keys DROP CONSTRAINT IF EXISTS keys_purpose_check;
ALTER TABLE keys ADD CONSTRAINT keys_purpose_check
    CHECK (purpose IN ('encrypt_decrypt', 'authenticate_verify', 'key_wrap'));
