
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;

/**
 * Main class to run Crypto app.
 * @author Seoungdeok Jeon
 * @author Tatiana Linardopoulou
 *
 */
public class Main {

	final static Scanner input = new Scanner(System.in);
	
	static String inputOption;
	static String outputOption;

	/**
	 * Calls encryption/decryption methods, interacts with user.
	 * @param args
	 */
	public static void main(String[] args) throws FileNotFoundException {
		System.out.println("Welcome to our cryptography program!\n"
				+ "Please select one of the following options by typing the associated number into your console:\n"
				+"1: I want a cryptographic hash.\n"
				+"2: I want a symmetric encryption.\n"
				+"3: I want a decryption of a symmetric cryptogram.\n"
				+"4: I want an authentication tag (MAC).\n"
				+"5: I want to generate an elliptic key pair.\n"
				+"6: I want to encrypt a file under a given elliptic public key.\n"
				+"7: I want to decrypt a given elliptic-encrypted file.\n"
				+"8: I want to generate a signature.\n"
				+"9: I want to verify a file and its signature.");
		String progOption = input.nextLine();
		System.out.println("Please select one of the following INPUT options: \n1: I want to type the input into the console.\n2: I want to use a file as input.");
		inputOption = input.nextLine();
		outputOption = outputOption();
		
		if (progOption.equals("1")) {
				hashInput();
		} else if (progOption.equals("2")) {
				symmEncr();
		} else if (progOption.equals("3")) {
				symmDecr();
		} else if (progOption.equals("4")) {
				mac();
		} else if (progOption.equals("5")) { 
				keyPair();
		} else if (progOption.equals("6")) {
				encryptFileECC();
		} else if (progOption.equals("7")) {
				decryptFileECC();
		} else if (progOption.equals("8")) {
				signData();
		} else if (progOption.equals("9")) {
				verifySign();
		} else {
				System.out.println("You have not picked a valid option. Program exiting.");
				System.exit(0);
		}
	}


	/**
	 * Displays output choices in console.
	 * @return 
	 */
	private static String outputOption() {
		System.out.println("Please select one of the following OUTPUT options:\n1: I want to see the output in the console.\n2: I want to save the output to a file.");
		return input.nextLine();
	}

	/**
	 * Get input data from console, return it as a byte array.
	 * @return A byte array containing input data.
	 */
	private static byte[] consoleInput() {
		String inputData = input.nextLine();
		return inputData.getBytes();
	}

	/**
	 * Get input data from file path, return it as a byte array.
	 * @return A byte array containing data from file.
	 */
	private static byte[] fileInput() {
		ArrayList<Byte> dataArray = new ArrayList<Byte>();
		String loc = input.nextLine();
		try {
			FileInputStream fileInput = new FileInputStream(loc);
			byte[] b = new byte[1];
			while (true) {
				int i = fileInput.read(b);
				if (i == -1) break;
				dataArray.add(b[0]);
			}
			fileInput.close();
		} catch (Exception e) {
			System.out.println("Invalid file.");
			System.exit(0);
		}
		byte[] data = new byte[dataArray.size()];
		for (int i = 0; i < dataArray.size(); i++) {
			data[i] = dataArray.get(i);
		}
		return data;
	}
	
	/**
	 * Asks the user for folder path.
	 * @return output file path.
	 */
	private static String outputLoc() {
		System.out.println("Please type in the exact output folder path: ");
		return input.nextLine();
	}
	
	/**
	 * Writes output data to provided file path.
	 * @param path The location to which the file should be written.
	 * @param data The data to write to file.
	 */
	private static void fileOutput(String path, byte[] data) {
		try {
			FileOutputStream output = new FileOutputStream(new File(path));
			output.write(data);
			output.close();
			System.out.println("Success! Your file has been created.");
		} catch (FileNotFoundException e) {
			System.out.println("Invalid file location.");
			e.printStackTrace();
			System.exit(0);
		} catch (IOException e) {
			System.out.println("Invalid input.");
			e.printStackTrace();
			System.exit(0);
		}
	}

	
	/**
	 * Gets the message/data from the user.
	 * @param inputOption file or console input
	 * @return byte array representation of the message/data
	 */
	private static byte[] getMessage(String inputOption) {
		System.out.println();
		if(inputOption.equals("1")) { 
			System.out.print("Please type the message: ");
			return consoleInput();
		} else if (inputOption.equals("2")) {
			System.out.print("Please type the message file path: ");
			return fileInput();
		} else {
			System.out.println("You have not picked a valid INPUT option. Program exiting.");
			System.exit(0);
			return null;
		}
	}
	
	/**
	 * Gets the cryptogram from the user.
	 * File input of console input of data.
	 * @param inputOption file or console input
	 * @return byte array representation of the cryptogram
	 */
	private static byte[] getCrypto(String inputOption) {
		System.out.println();
		if(inputOption.contentEquals("1")) { 
			System.out.print("Please type the cryptogram: ");
			return consoleInput();
		} else if (inputOption.equals("2")) {
			System.out.print("Please type the cryptogram file path: ");
			return fileInput();
		} else {
			System.out.println("You have not picked a valid INPUT option. Program exiting.");
			System.exit(0);
			return null;
		}
	}
	
	/**
	 * Gets password or key from the user.
	 * @param inputOption file or console input
	 * @return byte array representation of password/key
	 */
	private static byte[] getKey(String inputOption) {
		System.out.println();
		if(inputOption.equals("1")) { 
			System.out.print("Please type the password/key: ");
			return consoleInput();
		} else if(inputOption.equals("2")) {
			System.out.print("Please type the password/key file path: ");
			return fileInput();
		} else {
			System.out.println("You have not picked a valid INPUT option. Program exiting.");
			System.exit(0);
			return null;
		}
	}
	
	/**
	 * Gets the public key from the user.
	 * @param inputOption file or console input
	 * @return byte array representation of public key
	 */
	private static byte[] getPbKey(String inputOption) {
		System.out.println();
		if(inputOption.equals("1")) { 
			System.out.print("Please type the public key: ");
			return consoleInput();
		} else if(inputOption.equals("2")){
			System.out.print("Please type the public key file path: ");
			return fileInput();
		} else {
			System.out.println("You have not picked a valid INPUT option. Program exiting.");
			System.exit(0);
			return null;
		}
	}
	
	/**
	 * Gets the signature from the user.
	 * @param inputOption file or console input
	 * @return byte array representation of the digital signature.
	 */
	private static byte[] getSign(String inputOption) {
		System.out.println();
		if(inputOption.equals("1")) { 
			System.out.print("Please type the signature: ");
			return consoleInput();
		} else if (inputOption.equals("2")) {
			System.out.print("Please type the signature file path: ");
			return fileInput();
		} else {
			System.out.println("You have not picked a valid INPUT option. Program exiting.");
			System.exit(0);
			return null;
		}
	}


	/**
	 * Helper method to get input data from user and call hash method in SHA3 class.
	 */
	private static void hashInput() {
		byte[] m = getMessage(inputOption);
		byte[] crp = SHA3.hashKMACXOF256(m);
		if (outputOption.equals("1")) {
			System.out.println("Result: " + SHA3.bytesToHex(crp));
		} else if(outputOption.equals("2")) {
			String path = outputLoc();
			fileOutput(path + "\\hash.txt", crp);
		} else {
			System.out.println("You have not picked a valid OUTPUT option. Program exiting.");
			System.exit(0);
		}	
	}
	

	/**
	 * Helper method to get input data from user and call symmetric encryption method.
	 * Either prints result to console or file depending on user's choice.
	 */
	private static void symmEncr() {
		byte[] key = getKey(inputOption);
		byte[] m = getMessage(inputOption);
		byte[] crp = null;
		try {
			crp = SymmetricEncryptDecrypt.symmEncrypt(key, m, outputOption);
		} catch (IOException e) {
			e.printStackTrace();
		}
		if (outputOption.equals("1")) {
			System.out.print("\nEncryption: " + SHA3.bytesToHex(crp));	
		} else if(outputOption.equals("2")){ 
			String path = outputLoc();
			fileOutput(path + "\\crp.txt", crp);
		} else {
			System.out.println("You have not picked a valid OUTPUT option. Program exiting.");
			System.exit(0);
		}
	}

	/**
	 * Helper method to get input data from user and call symmetric decryption method.
	 * Either prints result to console or file depending on user's choice.
	 */
	private static void symmDecr() {
		byte[] crp = getCrypto(inputOption);
		byte[] key = getKey(inputOption);
		byte[] z = Arrays.copyOfRange(crp, 0, 64);			
		byte[] c = Arrays.copyOfRange(crp, 64, crp.length-64);
		byte[] t = Arrays.copyOfRange(crp, crp.length-64, crp.length);
		byte[] m = null;
		try {
			m = SymmetricEncryptDecrypt.symmDecrypt(z, key, c, t);
		} catch (IOException e) {
			e.printStackTrace();
		}
		if (outputOption.equals("1")) {
			System.out.println("Decryption result: " + SHA3.hexToStr(SHA3.bytesToHex(m)));
		} else if(outputOption.equals("2")) {
			String path = outputLoc();
			fileOutput(path + "\\decrp.txt", m);
		} else {
			System.out.println("You have not picked a valid OUTPUT option. Program exiting.");
			System.exit(0);
		}
	}
	
	/**
	 * Helper method to get input data from user and call mac method in SHA3 class.
	 */
	private static void mac() {
		byte[] key = getKey(inputOption);
		byte[] m = getMessage(inputOption);
		byte[] crp = SHA3.mac(key, m);
		if (outputOption.equals("1")) {
			System.out.println("Result: " + SHA3.bytesToHex(crp));
		} else if(outputOption.equals("2")) {
			String path = outputLoc();
			fileOutput(path + "\\mac.txt", crp);
		} else {
			System.out.println("You have not picked a valid OUTPUT option. Program exiting.");
			System.exit(0);
		}	
	}

	/**
	 * Helper method to get input data from user and call keyPair method in ECC class.
	 * Either prints result to console or file depending on user's choice. 
	 */
	private static void keyPair() {
		byte[] key = getKey(inputOption);
		ECPoint res = ECC.keyPair(key);
		if (outputOption.equals("1")) {
			System.out.println("Result: " + SHA3.bytesToHex(res.ptToBytes()));
		} else if(outputOption.equals("2")) {
			String path = outputLoc();
			fileOutput(path + "\\pubkey.txt", res.ptToBytes());
		} else {
			System.out.println("You have not picked a valid OUTPUT option. Program exiting.");
			System.exit(0);
		}
	}

	/**
	 *Helper method to get input data from user and call ECC encryption method.
	 * Either prints result to console or file depending on user's choice. 
	 */
	private static void encryptFileECC() {
		byte[] b = getPbKey(inputOption);
		byte[] x = new byte[b.length - 1];
		for (int i = 0; i < x.length; i++) {
			x[i] = b[i];
		}
		boolean lsbEven = b[b.length - 1] == 1;
		ECPoint v = new ECPoint(new BigInteger(x), lsbEven);
		byte[] m = getMessage(inputOption);
		byte[] crp = null;
		try {
			crp = ECC.ECEncrypt(v, m, outputOption);
		} catch (IOException e) {
			e.printStackTrace();
		}
		if (outputOption.equals("1")) {
			System.out.print("\nEncryption: " + SHA3.bytesToHex(crp));
		} else if(outputOption.equals("2")) { 
			String path = outputLoc();
			fileOutput(path + "\\eccrp.txt", crp);
		} else {
			System.out.println("You have not picked a valid OUTPUT option. Program exiting.");
			System.exit(0);
		}
	}

	/**
	 * Helper method to get input data from user and call ECC decryption method.
	 * Either prints result to console or file depending on user's choice.
	 */
	private static void decryptFileECC() {
		byte[] crp = getCrypto(inputOption);
		byte[] pb = new byte[67];
		for (int i = 0; i < 67; i++) {
			pb[i] = crp[i];
		}
		byte[] x = new byte[pb.length - 1];
		for (int i = 0; i < x.length; i++) {
			x[i] = pb[i];
		}
		boolean lsbEven = pb[pb.length - 1] == 1;
		ECPoint Z = new ECPoint(new BigInteger(x), lsbEven);			
		byte[] t = new byte[64];
		byte[] c = new byte[crp.length-t.length-pb.length];
		for (int i = 67; i < crp.length - 64; i++) c[i-67] = crp[i];
		for (int i = crp.length - 64; i < crp.length; i++) t[i - (crp.length - 64)] = crp[i];
		byte[] key = getKey(inputOption);
		byte[] m = ECC.ECDecrypt(key, Z, c, t);
		if (outputOption.equals("1")) {
			System.out.println("Decryption: " + SHA3.hexToStr(SHA3.bytesToHex(m)));
		} else if(outputOption.equals("2")) {
			String path = outputLoc();
			fileOutput(path + "\\ecdecrp.txt", m);
		} else {
			System.out.println("You have not picked a valid OUTPUT option. Program exiting.");
			System.exit(0);
		}
	}

	/**
	 * Helper method to generate a signature.
	 * Either prints result to console or file depending on user's choice. 
	 */
	private static void signData() {
		byte[] m = getMessage(inputOption);
		byte[] k = getKey(inputOption);
		byte[] s = null;
		try {
			s = ECC.sign(m, k);
		} catch (IOException e) {
			e.printStackTrace();
		}
		if (outputOption.equals("1")) {
			System.out.println("Result: " + SHA3.bytesToHex(s));
		} else if(outputOption.equals("2")) {
			String path = outputLoc();
			fileOutput(path + "\\sign.txt", s);
		} else {
			System.out.println("You have not picked a valid OUTPUT option. Program exiting.");
			System.exit(0);
		}		
	}

	/**
	 * Helper method to verify a data file and its signature file.
	 * Displays validity of signature. 
	 */
	private static void verifySign() {
		byte[] s = getSign(inputOption);
		byte[] m = getMessage(inputOption);
		byte[] b = getPbKey(inputOption);
		byte[] x = new byte[b.length - 1];
		for (int i = 0; i < x.length; i++) {
			x[i] = b[i];
		}
		boolean lsbEven = b[b.length - 1] == 1;
		ECPoint v = new ECPoint(new BigInteger(x), lsbEven);
		boolean isValid = ECC.verify(s, m, v);
		if (isValid) {
			System.out.println("Signature is valid.");
		} else {
			System.out.println("Signature is not valid.");
		}
	}
}
