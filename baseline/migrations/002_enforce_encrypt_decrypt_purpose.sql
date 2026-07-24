-- Historical migration. Migration 004 later adds the protocol-neutral
-- key_wrap purpose for imported KEKs.
-- Historical signing labels described the same underlying DEK material.
UPDATE keys SET purpose = 'encrypt_decrypt' WHERE purpose <> 'encrypt_decrypt';
ALTER TABLE keys DROP CONSTRAINT IF EXISTS keys_purpose_check;
ALTER TABLE keys ADD CONSTRAINT keys_purpose_check CHECK (purpose = 'encrypt_decrypt');
