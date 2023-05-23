import java.util.Arrays;

/**
 * Java implementation of SHA3 and the derived function SHAKE256.
 * Heavily inspired by Markku-Juhani O. Saarinen's C implementation.
 * Based on specifications in NIST FIPS 202 and NIST SP 800-185.
 * 
 * @author Markku-Juhani O. Saarinen (original C implementation)
 * @author Tatiana Linardopoulou
 * @author Seoungdeok Jeon
 *
 */
public class SHA3 {
	
	/**
	 * Number of Keccacf rounds.
	 */
	private static int KECCAKF_ROUNDS = 24;
	
	/**
	 * 8-bit bytes.
	 */
	private byte[] b = new byte[200];
	
	/**
	 * 64-bit words.
	 */
	private long[] st = new long[25];
	
	/**
	 * Ints that don't overflow.
	 */
	private int pt, rsiz, mdlen;
	
	/**
	 * Right encode only used to encode zero.
	 */
	private static final byte[] RIGHT_ENCODE = {(byte) 0x00, (byte) 0x01};
	
	/**
	 * Left encode for encode zero.
	 */
	private static final byte[] LEFT_ENCODE_0 = {(byte) 0x01, (byte) 0x00};
	
	/**
	 * flag b/ween 
	 */
	private boolean KMAC = false;
	
	/**
	 * flag b/ween KMAC & KMACXOF 
	 */
	private boolean XOF = false;
	
	/**
	 * Round constants for KeccakF (24 total).
	 */
	private static final long[] keccakf_rndc = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
            0x8000000080008000L, 0x000000000000808BL, 0x0000000080000001L,
            0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
            0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
            0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
            0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };
	
	/**
	 * Rho function rotation offsets.
	 */
    private static final int[] keccakf_rotc = {
            1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
            27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
    };

    /**
     * Pi lane shifts.
     */
    private static final int[] keccakf_piln = {
            10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
            15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
    };
    
    /**
     * Default constructor
     */
    public SHA3() {}
	
	
	/**
	 * Rotates 64-bit long x by y positions to the left
	 * 
	 * @param x a 64-bit long
	 * @param y left rotation amount
	 * @return 64 bit long x rotated by y positions
	 */
	private static long ROTL64(long x, int y) {
		return x << y | (x >>> (64 - y));
	}
	
	/**
	 * Apply Keccakf to input state array
	 * @param v byte array (state array)
	 */
	private void sha3_keccakf(byte[] v) {
		
		// Endianess conversion and cast bytes in v[] to longs in st[]
	    for (int i = 0, j = 0; i < 25; i++, j +=8) {
	        st[i] = (((long) v[j+0] & 0xFFL))      | (((long) v[j+1] & 0xFFL) << 8) |
	        	(((long) v[j+2] & 0xFFL) << 16) | (((long) v[j+3] & 0xFFL) << 24) |
	        	(((long) v[j+4] & 0xFFL)  << 32)  | (((long) v[j+5] & 0xFFL) << 40) |
	        	(((long) v[j+6] & 0xFFL) << 48) | (((long) v[j+7] & 0xFFL) << 56);
	    }
	    
	    // actual iteration
	    for (int r = 0; r < KECCAKF_ROUNDS; r++) {
	    	long t;
	    	long[] bc = new long[5];

	        // Theta
	        for (int i = 0; i < 5; i++)
	            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];

	        for (int i = 0; i < 5; i++) {
	            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
	            for (int j = 0; j < 25; j += 5) {
	                st[j + i] ^= t;
	            }
	        }

	        // Rho Pi
	        t = st[1];
	        for (int i = 0; i < 24; i++) {
	            int j = keccakf_piln[i];
	            bc[0] = st[j];
	            st[j] = ROTL64(t, keccakf_rotc[i]);
	            t = bc[0];
	        }

	        //  Chi
	        for (int j = 0; j < 25; j += 5) {
	            for (int i = 0; i < 5; i++) {
	                bc[i] = st[j + i];
	            }
	            for (int i = 0; i < 5; i++) {
	                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
	            }
	        }

	        //  Iota
	        st[0] ^= keccakf_rndc[r];
	    }
	    
	 // Endianess conversion and cast longs in st[] to bytes in v[].
	    for (int i = 0, j = 0; i < 25; i++, j +=8) {
	       long t = st[i];
	        v[j+0] = (byte)((t) & 0xFF);
	        v[j+1] = (byte)((t >> 8) & 0xFF);
	        v[j+2] = (byte)((t >> 16) & 0xFF);
	        v[j+3] = (byte)((t >> 24) & 0xFF);
	        v[j+4] = (byte)((t >> 32) & 0xFF);
	        v[j+5] = (byte)((t >> 40) & 0xFF);
	        v[j+6] = (byte)((t >> 48) & 0xFF);
	        v[j+7] = (byte)((t >> 56) & 0xFF);
	    }	    
	    
	}
	/**
	 * Encodes the integer x as a byte string in a way that can be unambiguously parsed
	 * from the beginning of the string, as specified per NIST SP 800-185 sec. 2.3.1
	 * 
	 * Validity Conditions: 0 <= x < 2^2040
	 * @param x integer x
	 * @return O byteString representation of x
	 */
	private static byte[] left_encode(int x) {
		//1. Let n be the smallest positive integer for which 2^8n > x.
		  int n = 1;
	      while ((1 << (8*n)) <= x) {
	            n++;
	      }
	      
	      byte[] O = new byte[n+1];
	      
	      for (int i = n; i >=1; i--) {
	    	  //2. Let x1, x2, …, xn be the base-256 encoding of x satisfying:x = sum 2^8(n-i)xi, for i = 1 to n. 
	    	  //3. Let Oi = enc8(xi), for i = 1 to n. 
	    	  O[i] = (byte)(x & 0xFF);
	    	  x = x >>> (8);
	      }
	      //4. Let O0 = enc8(n).
	      O[0] = (byte)n;
	      
	      //5.Return O 
	      return O;
	}
	
	/**
	 * Encodes bit strings in a way that may be parsed unambiguously 
	 * from the beginning of the string, S, as specified per NIST SP 800-185 sec. 2.3.2
	 * 
	 * Validity Conditions: 0 <= len(S) < 2^2040
	 * @param S the byte array of the string to encode
	 * @return SPrime the encoding of S (left_encode(len(S)) || S)
	 */
	private static byte[] encode_string(byte[] S) {
		int lenS;
		byte[] leftEncS;
		
		if (S == null) {
			lenS = 0;
			leftEncS = LEFT_ENCODE_0;
		} else {
			lenS = S.length;
			//left_encode(len(S))
			leftEncS = left_encode(lenS << 3);
		}
		//1. Return left_encode(len(S)) || S
		byte[] SPrime = Arrays.copyOf(leftEncS, leftEncS.length + lenS);	
		System.arraycopy(SPrime, 0, SPrime, leftEncS.length, lenS);
		return SPrime;	
	}
	
	/**
	 * Prepends an encoding of the integer w to an input string X, 
	 * then pads the result with zeros until it is a byte string 
	 * whose length in bytes is a multiple of w, as specified per NIST SP 800-185 sec. 2.3.3
	 * 
	 * Validity Conditions: w > 0
	 * @param X byte array of the string to pad
	 * @param w encoding integer
	 * @return z the padded byte array of X 
	 */
	private static byte[] bytepad(byte[] X, int w) {
		//1. z = left_encode(w) || X.
		byte[] leftEncW = left_encode(w);
		//"pad results w/0's until z is a byte string whose length is a mult of w"
		int zLen = leftEncW.length + X.length + (w - (leftEncW.length + X.length) % w);
		byte[] z = new byte[zLen];
		System.arraycopy(leftEncW, 0, z, 0, leftEncW.length);
		System.arraycopy(X, 0, z, leftEncW.length, X.length);
		//2. while len(z) mod 8 != 0: z = z || 0
		//3. while (len(z)/8) mod w != 0: z = z || 00000000
		for (int i = leftEncW.length + X.length; i < zLen; i++) {
			z[i] = (byte)0;
		}
		//4. return z
		return z;
	}
	
	/**
     * Initializes SHAKE256 sponge.
     * 
     */
    public void initSHAKE256() {
        Arrays.fill(b, (byte) 0);
        mdlen = 32; 
        rsiz = 200 - (2 * mdlen);
        pt = 0;
        KMAC = false;
        XOF = false;
    }
	
    /**
     * Initializes cSHAKE256 sponge.
     * 
     * Validity Conditions: len(N)< 2^2040 and len(S)< 2^2040
     * @param N function name bitstring 
     * @param S customization bitstring
     */
    public void initcSHAKE256(byte[] N, byte[] S) {
        initSHAKE256();
        if((N != null && N.length != 0) || (S != null && S.length != 0)) {
        	XOF = true;
        	//Concatenate N and S
        	byte[] temp = new byte[N.length + S.length];
        	System.arraycopy(N, 0, temp, 0, N.length);
        	System.arraycopy(S, 0, temp, N.length, S.length);
        	//136 --> Keccak[512]
        	byte[] p = bytepad(temp, 136);
        	update(p, p.length);
        }
        
    }
    
    /**
     * Initializes KMACXOF256 sponge.
     * 
     * Validity Conditions: len(K)< 2^2040 and len(S)< 2^2040
     * @param K MAC key bitstring 
     * @param S customization bitstring
     */
    public void initKMACXOF256(byte[] K, byte[] S) {
    	//136 --> Keccak[512]
    	byte[] encStrK = bytepad(encode_string(K), 136);
    	initcSHAKE256("KMAC".getBytes(), S);
    	KMAC = true;
    	update(encStrK, encStrK.length);	
    }
	
	/**
	 * Updates sponge 
	 * 
	 * @param data input byte array
	 * @param len length of input byte array
	 */
	private void update(byte[] data, int len) {
		int j = pt;
        for (int i = 0; i < len; i++) {
        	b[j++] ^= data[i];
            if (j >= rsiz) {
                sha3_keccakf(b);
                j = 0;
            }
        }
        pt = j;
	}
	
	/**
	 * Creates encoded data block from sponge.
	 * @param out encoded data
	 * @param len length of encoded data
	 */
	private void shake_out(byte[] out, int len) {
        int j = pt;
        for (int i = 0; i < len; i++) {
            if (j >= rsiz) {
                sha3_keccakf(b);
                j = 0;
            }
            out[i] = b[j++];
        }
        pt = j;
    }
	
	/**
	 * Switch from KMAC to KMACXOF (extensible output functionality).
	 */
	public void shake_xof() {
		if (KMAC = true) {
			update(RIGHT_ENCODE, RIGHT_ENCODE.length);
		}
		if (XOF = true) {
			b[pt] ^= (byte) 0x04;
		} else {
			b[pt] ^= (byte) 0x1F;
		}
		b[rsiz - 1] ^= (byte) 0x80;
		sha3_keccakf(b);
		pt = 0;
	}
	
	/**
	 * Returns the result of a call to SHAKE (if N and S are both empty strings),
	 * or returns the result of a call to KECCAK[512] with a padded encoding of N and S 
	 * concatenated to the input string X. As specified per NIST SP 800-185 sec.3.3
	 * 
	 * Validity Conditions: len(N)< 2^2040 and len(S)< 2^2040
	 * @param X the main input bitstring.
	 * @param L the requested output length in bits (integer)
	 * @param N function name bitstring
	 * @param S customization bitstring
	 * @return hash value
	 */
	public static byte[] cSHAKE256(byte[] X, int L, byte[] N, byte[] S) {
		SHA3 sha3 = new SHA3();
		byte[] result = new byte[L >>> 3];
		sha3.initcSHAKE256(N, S);
		sha3.update(X, X.length);
		sha3.shake_xof();
		sha3.shake_out(result, L >>> 3);
		
		return result;	
	}
	
	/**
	 * Keccak Message Authentication Code with extensible output.
	 * As specified per NIST SP 800-185 sec.4.3.1
	 * 
	 * Validity Conditions: len(N)< 2^2040 and len(S)< 2^2040
	 * @param K MAC key bitstring.
	 * @param X the main input bitstring.
	 * @param L the requested output length in bits (integer)
	 * @param S customization bitstring
	 * @return 
	 */
	public static byte[] KMACXOF256(byte[] K, byte[] X, int L, byte[] S) {
		SHA3 sha3 = new SHA3();
		byte[] result = new byte[L >>> 3];
		sha3.initKMACXOF256(K, S);
		sha3.update(X, X.length);
		sha3.shake_xof();
		sha3.shake_out(result, L >>> 3);
		return result;	
	}
	
	
	/**
	 * Computes a plain cryptographic hash of the user input.
	 * @param m a byte array of input to hash
	 * @return h the hash
	 */
	public static byte[] hashKMACXOF256(byte[] m) {
		// h = KMACXOF256(“”, m, 512, “D”)
		byte[] h = KMACXOF256("".getBytes(), m, 512, "D".getBytes()); 
		return h;
	}
	
	/**
	 * Computes an authentication tag (MAC) of a given input under a given passphrase.
	 * @param pw the passphrase
	 * @param m a byte array of input
	 * @return t the authentication tag . 
	 */
	public static byte[] mac(byte[] pw, byte[] m) {
		//t = KMACXOF256(pw, m, 512, “T”)
		byte[] t = KMACXOF256(pw, m, 512, "T".getBytes());
		return t;
	}
	
	/**
	 * Helper method to convert decimal byte array to hex.
	 * @param input array
	 * @return hex representation of input array
	 */
	public static String bytesToHex(byte[] input) {
		char[] hex = "0123456789ABCDEF".toCharArray();
		char[] chars = new char[input.length * 2];
		for (int j = 0; j < input.length; j++ ) {
			int v = input[j] & 0xFF;
			chars[j * 2] = hex[v >>> 4];
			chars[j * 2 + 1] = hex[v & 0x0F];
		}
		return new String(chars);
	}
	
	/**
	 * Helper method to convert hex string to ascii representation
	 * for console output.
	 * 
	 * @param hex hex string
	 * @return ascii representation of hex string
	 */
	public static String hexToStr(String hex) 
	{ 
		String str = ""; 
		for (int i = 0; i < hex.length(); i += 2) { 
			String temp = hex.substring(i, i + 2); 
			char c = (char)Integer.parseInt(temp, 16); 
			str = str + c; 
		} 
		return str; 
	}
	
}
