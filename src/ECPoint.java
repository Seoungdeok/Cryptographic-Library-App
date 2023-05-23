
import java.math.BigInteger;

/**
 * Class for ECPoint object and elliptic curve arithmetic.
 * Includes method for computing square roots modulo p, 
 * as provided by Dr. Paulo Barreto.
 * 
 * @author Dr. Paulo Barreto
 * @author Tatiana Linardopoulou
 * @author Seoungdeok Jeon
 */
public class ECPoint {


	/**
	 * x-coordinate of point.
	 */
	private BigInteger myX;
	
	/**
	 * y-coordinate of point.
	 */
	private BigInteger myY;
	
	/**
	 * Parameter for Edwards curve.
	 * P := (2^521) - 1, a Mersenne prime defining the finite field Fp.
	 */
	private static final BigInteger P = BigInteger.valueOf(2L).pow(521).subtract(BigInteger.ONE);
	
	/**
	 * Parameter for Edwards curve.
	 * d value to satisfy curve equation:x^2+y^2 = 1+dx^2y^2
	 */
	private static final BigInteger D = new BigInteger("-376014");
	
	/**
	 * Number of points n on E521 Edwards Curve.
	 * n=4r, where: r= 2^519− 337554763258501705789107630418782636071904961214051226618635150085779108655765.
	 */
	public static final BigInteger R = BigInteger.valueOf(2).pow(519).subtract(new BigInteger("337554763258501705789107630418782636071904961214051226618635150085779108655765"));
	
	/**
	 * Public generator G:=(x0, y0) x0=4, y0=unique even number.
	 */
	public static ECPoint G = new ECPoint(BigInteger.valueOf(4L), false);
	
	/**
	 * Constructor for the neutral element.
	 * x=0, y=1
	 */
	public ECPoint() {
		this(BigInteger.ZERO, BigInteger.ONE);
	}
	
	/**
	 * Constructor for a curve point given its x and y coordinates.
	 * 
	 * @param x the x-coord of the point
	 * @param y the y-coord of the point
	 */
	public ECPoint(BigInteger x, BigInteger y) {
		if (isValid(x, y)) {
			myX = x;
			myY = y;
		} else {
			throw new IllegalArgumentException("These point coordinates do not satisfy the curve equation.");
		}
	}
	

	/**
	 * Constructor for a curve point from its x coordinate 
	 * and the least significant bit of y.
	 * 
	 * @param x the x-coord of the point
	 * @param boolean lsb desired least significant bit (true: 1, false: 0).
	 */
	public ECPoint(BigInteger x, boolean lsb) {
		myX = x;
		
		//From Project Description:y=±√(1−𝑥^2)/(1+376014*(𝑥^2)) mod 𝑝.
		
		//Numerator = 1-x^2
		BigInteger num = BigInteger.ONE.subtract(x.modPow(BigInteger.valueOf(2), P));
		//Denominator = (1-d*(𝑥^2))
		BigInteger denom = BigInteger.ONE.add(BigInteger.valueOf(376014).multiply(x.modPow(BigInteger.valueOf(2), P)));
		//y = sqrt((1−𝑥^2)/(1-d*(𝑥^2))modP
		BigInteger y = sqrt(num.multiply(denom.modInverse(P)), P, lsb);
		myY = y;	
	}
	
	/**
	 * Getter for x coord
	 * @return the x coord this point
	 */
	public BigInteger getX() {
		return myX;
	}
	
	/**
	 * Getter for y coord
	 * @return the y coord this point
	 */
	public BigInteger getY() {
		return myY;
	} 
	
	/**
	 * Gets opposite point to input ECPoint.
	 * The opposite of a point (𝑥,𝑦) is the point (−𝑥,𝑦).
	 * @param point1 the input ECPoint
	 * @return the opposite ECPoint
	 */
	public ECPoint getOppositePt(ECPoint point1) {
		BigInteger negX = BigInteger.valueOf(-1).multiply(point1.myX).mod(P);
		BigInteger y = point1.myY;
		return new ECPoint(negX, y);
	}
	
	
	/**
	 * Helper method to check if x and y coords satisfy 
	 * curve equation:x^2+y^2 = 1+dx^2y^2
	 * 
	 * @param x the x-coord of the point
	 * @param y the y-coord of the point
	 * @return boolean true if point is on curve false otherwise.
	 */
	private boolean isValid(BigInteger x, BigInteger y) {
		BigInteger leftSide;
		BigInteger rightSide;
		
		//(x^2+y^2)modP
		leftSide = x.pow(2).add(y.pow(2)).mod(P);
		
		//(1+dx^2y^2)modP
		rightSide = BigInteger.ONE.add(D.multiply(x.pow(2).multiply(y.pow(2)))).mod(P);
		
		return leftSide.equals(rightSide);
	}
	
	/**
	 * Converts ECPoint obj into byte array, last byte is 1 if the y-val is odd, other y even.
	 * @return res byte array representation of ECPoint
	 */
	public byte[] ptToBytes() {
		byte[] xbt = myX.toByteArray();
		int zer = 66 - xbt.length;
		byte ybit = 1;
		if (myY.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO)) {
			ybit = 0;
		}
		byte[] res = new byte[67];
		int i;
		for (i = 0; i < zer; i++) {
			res[i] = 0;
		}
		for (i = 0; i < 66; i++) {
			res[i] = xbt[i - zer];
		}
		res[66] = ybit;
		return res;
	}
	
	/**
	 * Computes the sum of the current point and another point
	 * using Edwards point addition formula:
	 * (𝑥1,𝑦1)+(𝑥2,𝑦2)=(𝑥1𝑦2+𝑦1𝑥2/1+𝑑𝑥1𝑥2𝑦1𝑦2, 𝑦1𝑦2−𝑥1𝑥2/1−𝑑𝑥1𝑥2𝑦1𝑦2).
	 * @param otherPt the ECPoint to be added to this ECPoint
	 * @return the new ECPoint resulting from the summation
	 */
	public ECPoint getSum(ECPoint otherPt) {
		BigInteger x1 = myX;
		BigInteger y1 = myY;
		BigInteger x2 = otherPt.myX;
		BigInteger y2 = otherPt.myY;
		
		//New x-coord numerator = 𝑥1𝑦2+𝑦1𝑥2
		BigInteger xNum = x1.multiply(y2).add(y1.multiply(x2)).mod(P);
		//New x-coord denominator = 1+𝑑𝑥1𝑥2𝑦1𝑦2
		BigInteger xDenom = BigInteger.ONE.add(D.multiply(x1.multiply(x2.multiply(y1.multiply(y2))))).mod(P);
		//New x-coord
		BigInteger sumX = xNum.multiply(xDenom.modInverse(P)).mod(P);
		
		//New y-coord numerator = 𝑦1𝑦2−𝑥1𝑥2
		BigInteger yNum = y1.multiply(y2).subtract(x1.multiply(x2)).mod(P);
		//New y-coord denominator = 1−𝑑𝑥1𝑥2𝑦1𝑦2
		BigInteger yDenom = BigInteger.ONE.subtract(D.multiply(x1.multiply(x2.multiply(y1.multiply(y2))))).mod(P);
		//New y-coord
		BigInteger sumY = yNum.multiply(yDenom.modInverse(P)).mod(P);
		
		return new ECPoint(sumX, sumY);
	}
	
	/**
	 * Overriden to test ECPoints for equality 
	 * by comparing x and y vals.
	 * 
	 */
	@Override
	public boolean equals(Object o) {
		if (this.getClass() != o.getClass()) {
			return false;
		}
		ECPoint otherPt = (ECPoint) o;
		return myX.equals(otherPt.myX) && myY.equals(otherPt.myY);		
	}
	
	/**
	 * Multiplication by scalar, "Exponentiation" algorithm
	 * @param p the ECPoint to be multiplied
	 * @param scalar the scalar by which to multiply
	 * @return the scalar multiple of the ECPoint
	 */
	public static ECPoint multByScalar(BigInteger scalar, ECPoint p) {
		//V = P
		ECPoint V = p;
		String s = scalar.toString(2);
		//for i in range(k–1, -1, -1):
		for (int i = s.length() - 1; i >= 0; i--) {
			//V = V + V
			V = V.getSum(V);
			//if s[i] == 1:
			if (s.charAt(i) == '1') {
				//V = V + P
				V = V.getSum(p);
			}
		}
		//V = s·V
		return V;
	}
	

	/**
	* Compute a square root of v mod p with a specified
	* least significant bit, if such a root exists.
	*
	* @author Dr. Paulo Barreto
	* 
	* @param v the radicand.
	* @param p the modulus (must satisfy p mod 4 = 3).
	* @param lsb desired least significant bit (true: 1, false: 0).
	* @return a square root r of v mod p with r mod 2 = 1 iff lsb = true
	* if such a root exists, otherwise null.
	*/
	public static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
		assert (p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)
		if (v.signum() == 0) {
			return BigInteger.ZERO;
		}
		BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
		if (r.testBit(0) != lsb) {
			r = p.subtract(r); // correct the lsb
		}
		return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
	}
	
	
}
