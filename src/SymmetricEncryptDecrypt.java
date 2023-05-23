
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;


/**
 * Class for Symmetric Encryption and Decryption of files.
 * @author Seoungdeok Jeon
 * @author Tatiana Linardopoulou
 *
 */
public class SymmetricEncryptDecrypt {

	/**
	 * true if t' = t
	 */
	private static boolean isValid;
	
	
	/**
	 * Encrypts byte array under passphrase.
	 * 
	 * @param pass passphrase byte array
	 * @param m message byte array
	 * @param outputOption file or console output chosen
	 * @return cryptogram of message
	 * @throws IOException 
	 */
	public static byte[] symmEncrypt(byte[] pass, byte[] m, String outputOption) throws IOException{
		//z <-- Random(512)
		SecureRandom r = new SecureRandom();
		byte[] z = new byte[64];
		r.nextBytes(z);
		//(ke || ka) <-- KMACXOF256(z || pw, “”, 1024, “S”)
		byte[] keka = SHA3.KMACXOF256(mergeArrays(z, pass), "".getBytes(), 1024, "S".getBytes());
		//c <-- KMACXOF256(ke, “”, |m|, “SKE”) XOR m
		byte[] ke = Arrays.copyOfRange(keka, 0, 64);
		byte[] temp = SHA3.KMACXOF256(ke, "".getBytes(), m.length*8, "SKE".getBytes());
		byte[] c = new byte[m.length];
		for (int i = 0; i < m.length; i++) {
			c[i] = (byte) (temp[i] ^ m[i]);
		}
		//t <-- KMACXOF256(ka, m, 512, “SKA”)
		byte[] ka = Arrays.copyOfRange(keka, 64, 128);
		byte[] t = SHA3.KMACXOF256(ka, m, 512, "SKA".getBytes());
		//symmetric cryptogram: (z, c, t)
		ByteArrayOutputStream res = new ByteArrayOutputStream();
		res.write(z);
		res.write(c);
		res.write(t);
		return res.toByteArray();	
	}
	
	
	/**
	 * Decrypts cryptogram using passphrase.
	 * 
	 * @param z rand val used for encrypt
	 * @param pass passphrase byte array
	 * @param c ciphertext byte array
	 * @param t message auth code byte array
	 * @return decrypted message (byte array)
	 * @throws IOException 
	 */
	public static byte[] symmDecrypt(byte[] z, byte[] pass, byte[] c, byte[] t) throws IOException {
		//(ke || ka) <-- KMACXOF256(z || pw, “”, 1024, “S”)
		byte[] keka = SHA3.KMACXOF256(mergeArrays(z, pass), "".getBytes(), 1024, "S".getBytes());
		//m <-- KMACXOF256(ke, “”, |c|, “SKE”) XOR c
		byte[] temp = SHA3.KMACXOF256(Arrays.copyOfRange(keka, 0, 64), "".getBytes(), c.length*8, "SKE".getBytes());
		byte[] m = new byte[c.length];
		for (int i =0; i < c.length; i++) {
			m[i] = (byte) (c[i] ^ temp[i]);
		}
		//t’ <-- KMACXOF256(ka, m, 512, “SKA”)
		byte[] tp = SHA3.KMACXOF256(Arrays.copyOfRange(keka, 64, 128), m, 512, "SKA".getBytes());
		//accept if, and only if, t’ = t
		isValid = Arrays.equals(t, tp);
		if(isValid) {
			return m;
		} else {
			System.out.println("T does not equal t-prime.");
			return null;
		}
	}
	
	/**
	 * Helper method. Merges two arrays.
	 * @param a input byte array 1
	 * @param b input byte array 2
	 * @return merged byte array
	 * @throws IOException 
	 */
	public static byte[] mergeArrays(byte[] a, byte[] b) throws IOException {
		ByteArrayOutputStream res = new ByteArrayOutputStream();
		res.write(a);
		res.write(b);
		return res.toByteArray();
	}
}
