PBEWithMD5AndDES implementation using golang


Golang implementation:

```golang
func main() {
	salt := []byte{0xFF, 0x2B, 0x38, 0x30, 0xF8, 0x61, 0xEF, 0x99}
	password := "my_secret_password"
	iterations := 222
	originalText := "mythings"

	res, err := Encrypt(password, iterations, originalText, salt)
	fmt.Println("encripted", res, err)
	res, err = Decrypt(password, iterations, res, salt)
	fmt.Println("decripted", res, err)
}
```

Java equivalence:

```java
keySpec = new PBEKeySpec(password.toCharArray(), salt, iterations);
key = SecretKeyFactory.getInstance("PBEWithMD5AndDES").generateSecret(keySpec);
ecipher = Cipher.getInstance(key.getAlgorithm());
dcipher = Cipher.getInstance(key.getAlgorithm());
ecipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
dcipher.init(Cipher.DECRYPT_MODE, key, paramSpec);

byte[] enc = ecipher.doFinal(originalText);
String res = Base64.getEncoder().encodeToString(enc);
System.out.println("encripted " + res);

byte[] dec = Base64.getDecoder().decode(res);
dec = dcipher.doFinal(dec);
System.out.println("decripted " + dec);

```