
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;


/**
 * Class for Elliptic Curve Cryptography
 * @author Tatiana Linardopoulou
 * @author Seoungdeok Jeon
 *
 */
public class ECC {
	
	/**
	 * Number of points n on E521 Edwards Curve.
	 * n=4r, where: r= 2^519 - 337554763258501705789107630418782636071904961214051226618635150085779108655765.
	 */
	public static final BigInteger R = BigInteger.valueOf(2).pow(519).subtract(new BigInteger("337554763258501705789107630418782636071904961214051226618635150085779108655765"));
	
	
	/**
	 * Generates an elliptic key pair from a given passphrase. 
	 * @param pw passphrase used to generate key pair
	 */
	public static ECPoint keyPair(byte[] pw) {
		//s = KMACXOF256(pw, “”, 512, “K”);
		byte[] temp = SHA3.KMACXOF256(pw,"".getBytes(), 512, "K".getBytes());
		//s = 4s; s-->private key
		BigInteger s = BigInteger.valueOf(4L).multiply(new BigInteger(temp));
		//V = s*G; key pair: (s, V)
		ECPoint v = ECPoint.multByScalar(s, ECPoint.G);
		return v;
	}
	
	/**
	 * Encrypts user input under a given elliptic public key file.
	 * 
	 * @param v the public key
	 * @param m the input to be encrypted
	 * @param ouputOption console or file output choice
	 * @return byte array of cryptogram
	 * @throws IOException 
	 */
	public static byte[] ECEncrypt(ECPoint v, byte[] m, String outputOption) throws IOException {
		SecureRandom r = new SecureRandom();
		//k = Random(512)
		byte[] temp = new byte[64];
		r.nextBytes(temp);
		//k = 4k
		BigInteger k = BigInteger.valueOf(4L).multiply(new BigInteger(temp));
		//W = k*V
		ECPoint w = ECPoint.multByScalar(k, v);
		//Z = k*G
		ECPoint Z = ECPoint.multByScalar(k, ECPoint.G);
		//(ke || ka) = KMACXOF256(Wx, “”, 1024, “P”)
		byte[]keka = SHA3.KMACXOF256(w.getX().toByteArray(), "".getBytes(), 1024, "P".getBytes());
		//c = KMACXOF256(ke, “”, |m|, “PKE”) XOR m
		byte[] ke = Arrays.copyOfRange(keka, 0, 64);
		byte[] b = SHA3.KMACXOF256(ke, "".getBytes(), m.length*8, "PKE".getBytes());
		byte[] c = new byte[m.length];
		for (int i = 0; i < c.length; i++) {
			c[i] = (byte) (m[i] ^ b[i]);
		}
		//t = KMACXOF256(ka, m, 512, “PKA”)
		byte[] ka = Arrays.copyOfRange(keka, 64, 128);
		byte[] t = SHA3.KMACXOF256(ka, m, 512, "PKA".getBytes());
		byte[] z = Z.ptToBytes();
		//cryptogram: (Z, c, t)
		ByteArrayOutputStream res = new ByteArrayOutputStream();
		res.write(z);
		res.write(c);
		res.write(t);
		return res.toByteArray();	
	}
	
	/**
	 * Decrypts a given elliptic-encrypted file from a given password.
	 * 
	 * @param pw the password used to create pub key.
	 * @param Z ECPoint used for encrypt
	 * @param c ciphertext byte array
	 * @param t message auth code byte array
	 * @return decrypted message (byte array)
	 */
	public static byte[] ECDecrypt(byte[] pw, ECPoint Z, byte[] c, byte[] t) {
		//s = KMACXOF256(pw, “”, 512, “K”)
		byte[] temp = SHA3.KMACXOF256(pw, "".getBytes(), 512, "K".getBytes());
		//s = 4s
		BigInteger s = BigInteger.valueOf(4L).multiply(new BigInteger(temp));
		//W = s*Z
		ECPoint w = ECPoint.multByScalar(s, Z);
		//(ke || ka) = KMACXOF256(Wx, “”, 1024, “P”)
		byte[] keka = SHA3.KMACXOF256(w.getX().toByteArray(), "".getBytes(), 1024, "P".getBytes());
		//m = KMACXOF256(ke, “”, |c|, “PKE”) XOR c
		byte[] ke = Arrays.copyOfRange(keka, 0, 64);
		byte[] b = SHA3.KMACXOF256(ke, "".getBytes(), c.length*8, "PKE".getBytes());
		byte[] m = new byte[c.length];
		for (int i = 0; i < m.length; i++) {
			m[i] = (byte) (b[i] ^ c[i]);
		}
		//t’ = KMACXOF256(ka, m, 512, “PKA”)
		byte[] ka = Arrays.copyOfRange(keka, 64, 128);
		byte[] tp = SHA3.KMACXOF256(ka, m, 512, "PKA".getBytes());
		//accept if, and only if, t’ = t
		boolean isValid = Arrays.equals(t, tp);
		if(isValid) {
			return m;
		} else {
			System.out.println("t does not equal t-prime.");
			return null;
		}
	}
	
	/**
	 * Signs a given file from a given password and writes the signature to a file.
	 * 
	 * @param m the input file to sign
	 * @param pw given password
	 * @throws IOException 
	 */
	public static byte[] sign(byte[] m, byte[] pw) throws IOException {
		//s = KMACXOF256(pw, “”, 512, “K”)
		byte[] tempS = SHA3.KMACXOF256(pw, "".getBytes(), 512, "K".getBytes());
		//s = 4s
		BigInteger s = BigInteger.valueOf(4L).multiply(new BigInteger(tempS));
		//k = KMACXOF256(s, m, 512, “N”)
		byte[] tempK = SHA3.KMACXOF256(s.toByteArray(), m, 512, "N".getBytes());
		//k = 4k
		BigInteger k = BigInteger.valueOf(4L).multiply(new BigInteger(tempK));
		//U = k*G;
		ECPoint u = ECPoint.multByScalar(k, ECPoint.G);
		//h = KMACXOF256(Ux, m, 512, “T”)
		BigInteger h = new BigInteger(SHA3.KMACXOF256(u.getX().toByteArray(), m, 512, "T".getBytes()));
		//z = (k – hs) mod r
		BigInteger z = (k.subtract(h.multiply(s))).mod(R);
		//signature: (h, z)
		return (SymmetricEncryptDecrypt.mergeArrays(h.toByteArray(), z.toByteArray()));
	}
	
	/**
	 * Verifies a given data file and its signature file under a given public key file.
	 * @param sig signature byte array
	 * @param m message byte array
	 * @param V public key 
	 */
	public static boolean verify(byte[] hz, byte[] m, ECPoint V) {
		byte[] h = new byte[64];
		byte[] z = new byte[hz.length - 64];
		for (int i = 0; i < h.length; i++) {
			h[i] = hz[i];
		}
		for (int i = 0; i < z.length; i++) {
			z[i] = hz[64+i];
		}
		//z*G 
		ECPoint zG = ECPoint.multByScalar(new BigInteger(z), ECPoint.G);
		//h*V
		ECPoint hV = ECPoint.multByScalar(new BigInteger(h), V);
		//U = z*G + h*V
		ECPoint u = zG.getSum(hV);
		//accept if, and only if, KMACXOF256(Ux, m, 512, “T”) = h
		byte[] hp = SHA3.KMACXOF256(u.getX().toByteArray(), m, 512, "T".getBytes());
		boolean isValid = Arrays.equals(h, hp);
		return isValid;
	}
}
