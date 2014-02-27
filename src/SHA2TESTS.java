import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.text.DecimalFormat;

public class SHA2TESTS {
	
	final static int SHORT = 10;
	final static int LONG = 100;
	
	public static void main(String[] args) {
		
		if (args.length == 0) {
			
			System.out.println("NO ARGUMENTS GIVEN - RUNNING ALL TESTS");
			System.out.println();
			
			verifyHashOutputs();
			
			testPerformance(SHORT, 5 * 1000 * 1000);
			
		}
		
		else {
			
			if (args[0].contains("-verify")) verifyHashOutputs();
			else if (args[0].contains("-performance")) 
				if (args.length == 1 || args[1].contains("-s")) testPerformance(SHORT, 5 * 1000 * 1000);
				else if (args[1].contains("-l")) testPerformance(LONG, 5 * 1000 * 1000 * 1000);
				else printHelp();
			else printHelp();
			
		}
		
	}
	
	public static void printHelp() {
		
		System.out.println("SHA2 HASH TESTING PROGRAM");
		System.out.println("AUTHOR : ALEX FEATHER");
		System.out.println();
		System.out.println("USAGE:");
		System.out.println("SHA2TESTS");
		System.out.println("SHA2TESTS -verify");
		System.out.println("SHA2TESTS -performance -[short|long]");
		System.out.println();
		System.out.println("\t\tNO ARGUMENTS WILL RUN ALL OF THE TESTS");
		System.out.println("-verify\t\tUSED TO CHECK THAT THE OUTPUT OF THE HASHING FUNCTIONS ARE CORRECT");
		System.out.println("-performance\tUSED GENERATE MEAN TIMES TO HASH DATA");
		System.out.println("   -short\tSETS THE NUMBER OF HASHES PER LOOP TO 10 [DEFAULT]");
		System.out.println("   -long\tSETS THE NUMBER OF HASHES PER LOOP TO 100");
		
	}
	
	public static void verifyHashOutputs() {
		
		System.out.println("VERIFY HASH OUTPUTS");
		
		SHA sha2 = new SHA2();
		SHA sha2_op = new SHA2_OP();
		
		byte[] input, output = new byte[32];
		
		input = new byte[0];
		output = hexStringToBytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
		
		System.out.println("SHA2    : \"\"");
		
		verifyBothOutput(input, output, sha2, sha2_op);
		
		input = "The quick brown fox jumps over the lazy dog".getBytes();
		output = hexStringToBytes("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
		
		System.out.println("SHA2    : \"The quick brown fox jumps over the lazy dog\"");
		
		verifyBothOutput(input, output, sha2, sha2_op);
		
		input = "The quick brown fox jumps over the lazy dog.".getBytes();
		output = hexStringToBytes("ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c");
		
		System.out.println("SHA2    : \"The quick brown fox jumps over the lazy dog.\"");
		
		verifyBothOutput(input, output, sha2, sha2_op);
		
		System.out.println();
		
		String folder = "C:\\Users\\Alex\\workspace\\FinalYearProject\\testVectors\\";
		
		System.out.println("SHA256 SHORT MESSAGE");
		verifyTestVectors(folder + "SHA256ShortMsg.rsp", sha2, sha2_op);
		
		System.out.println("SHA256 LONG MESSAGE");
		verifyTestVectors(folder + "SHA256LongMsg.rsp" , sha2, sha2_op);
		
	}
	
	public static void verifyTestVectors(String file, SHA sha2, SHA sha2_op) {
		
		try {
			
			BufferedReader in = new BufferedReader(new InputStreamReader(new FileInputStream(file)));
			
			String line;
			int len, sha2_pass = 0, sha2_op_pass = 0;
			byte[] input, output;
			
			while ((line = in.readLine()) != null) {
				
				if (line.contains("Len")) {
					
					len = Integer.parseInt(line.split(" ")[2]);
					
					System.out.println(line);
					
					if ((line = in.readLine()) == null) break;
					
					input = hexStringToBytes(line.split(" ")[2].substring(0, len/4));
					
					System.out.println(line);
					
					if ((line = in.readLine()) == null) break;
					
					output = hexStringToBytes(line.split(" ")[2]);
					
					System.out.print("SHA2    : ");
					if (!outputCorrect(sha2   , input, output)) sha2_pass++;
					System.out.print("SHA2 OP : ");
					if (!outputCorrect(sha2_op, input, output)) sha2_op_pass++;
					
					System.out.println();
				}
				
			}
			
			System.out.print("SHA2    : ");
			if (sha2_pass == 0) System.out.print("ALL TESTS PASSED");
			else System.out.print("FAILED " + sha2_pass + " TESTS");
			
			System.out.print("\t");

			System.out.print("SHA2 OP : ");
			if (sha2_op_pass == 0) System.out.print("ALL TESTS PASSED");
			else System.out.print("FAILED " + sha2_op_pass + " TESTS");
			
			System.out.println();
			System.out.println();
			
			in.close();
			
		} catch (FileNotFoundException e) {
			System.out.println("COULD NOT OPEN TEST FILE: " + file);
		} catch (IOException e) {
			System.out.println("COULD NOT READ FROM FILE!");
		}
		
	}
	
	public static void verifyBothOutput(byte[] input, byte[] expected, SHA sha2, SHA sha2_op) {
		
		System.out.print("SHA2    : ");
		outputCorrect(sha2   , input, expected);
		System.out.print("SHA2 OP : ");
		outputCorrect(sha2_op, input, expected);
		System.out.println();
		
	}
	
	public static boolean outputCorrect(SHA sha, byte[] input, byte[] expected) {
		
		sha.update(input);
		
		byte[] output = sha.getHash();
		
		System.out.print(sha.printBytes(output));
		
		for (int i = 0; i < output.length; i++) {
			
			if (output[i] != expected[i]) {
				
				System.out.println("\t( FAIL! )");
				
				System.out.println("EXPECTED: " + sha.printBytes(expected));
				return false;
				
			}
			
		}
		
		System.out.println("\t( PASS )");
		return true;
		
	}
	
	public static void testPerformance(int count, long max_bytes) {
		
		System.out.println("START PERFORMANCE TESTS");
		
		SHA sha2 = new SHA2();
		SHA sha2_op = new SHA2_OP();
		
		long start, end;
		
		double averageTime, averageByteTime, averageByteSec, averageBlockTime;
		double averageTime_op, averageByteTime_op, averageByteSec_op, averageBlockTime_op;
		
		long blocks;
		boolean extraBlock;
		
		start = System.currentTimeMillis();
		
		boolean multiply = true;
		
		for (long length = 50000; length <= max_bytes; multiply = !multiply) {
			
			if (multiply) length *= 2;
			else length *= 5;
			
			extraBlock = (length % 64) > 56;

			blocks = length / 64 + 1;
			
			if (extraBlock) blocks ++;
			
			averageTime = averageHashTime(sha2, count, length);
			averageTime_op = averageHashTime(sha2_op, count, length);
			
			averageByteTime = (double)averageTime / (double) length;
			averageByteTime_op = (double)averageTime_op / (double)length;
			
			averageByteSec = (double) length / (double) averageTime;
			averageByteSec_op = (double) length / (double) averageTime_op;
			
			averageBlockTime = (double) averageTime / (double) blocks;
			averageBlockTime_op = (double) averageTime_op / (double) blocks;
			
			System.out.println(bytesToString(length) + " ( " + length + " bytes ) hashed " + count + " times");
		
			System.out.println("SHA2 AVERAGE\t\t" + mktime(averageTime));
			System.out.println("SHA2 BYTE TIME\t\t" + mktime(averageByteTime));
			System.out.println("SHA2 BYTE / MS\t\t" + new DecimalFormat("0.000000").format(averageByteSec));
			System.out.println("SHA2 BLOCK TIME\t\t" + mktime(averageBlockTime));
			System.out.println("SHA2 OP AVERAGE\t\t" + mktime(averageTime_op));
			System.out.println("SHA2 OP BYTE TIME\t" + mktime(averageByteTime_op));
			System.out.println("SHA2 OP BYTE / MS\t" + new DecimalFormat("0.000000").format(averageByteSec_op));
			System.out.println("SHA2 OP BLOCK TIME\t" + mktime(averageBlockTime_op));
			
			System.out.println();
			
		}
		
		end = System.currentTimeMillis();
		
		System.out.println("Total test took: " + mktime(end-start));
		
	}
	
	public static long averageHashTime(SHA sha, int count, long length) {
		
		long time = 0;
		long start, end;
		
		int percent10 = (int) (0.1 * (double) count);
		
		start = System.currentTimeMillis();
		
		for (int i = 0; i < count; i++) {
			time += timeHash(sha, length);
			
			if (i % percent10 == 0) System.out.print("- ");
			
		}
		
		end = System.currentTimeMillis();
		
		System.out.println("100% [" + mktime(end-start) + "]");
		
		
		
		return time / (long) count;
		
	}
	
	public static long timeHash(SHA sha, long length) {
		
		long start, end;
		
		start = System.currentTimeMillis();
		
		for (long i = 0; i < length; i++) sha.update((byte) 0x00);
		
		sha.getHash();
		
		end = System.currentTimeMillis();
		
		return end - start;
		
	}

	
	public static byte[] hexStringToBytes(String hexString) {
		
		byte[] b = new byte[hexString.length() / 2];
		
		for (int i = 0; i < hexString.length(); i+= 2) 
			b[i/2] = (byte) ((Character.digit(hexString.charAt(i  ), 16) * 16 )
							+ Character.digit(hexString.charAt(i+1), 16)      );
		
		return b;
		
	}
	
	public static String bytesToString(long bytes) {
		
		if (bytes < 1000) return bytes +"B";
		
		long KB = bytes / 1000;
		
		if (KB < 1000) return KB + "KB";
		
		long MB = KB / 1000;
		
		if (MB < 1000) return MB + "MB";
		
		long GB = MB / 1000;
		
		return GB + "GB";
		
	}
	
	public static String mktime(double totalMS) {
		
		if (totalMS < 1.0)
			return new DecimalFormat("0.000000").format(totalMS) + " ms" + "\t(" + totalMS + ")";
		
		double second = 1000.0;
		double minute = 60.0 * second;
		double hour   = 60.0 * minute;
		
		int hours = (int)(totalMS / hour);
		int minutes = (int)((totalMS - hours * hour) / minute);
		int seconds = (int)((totalMS - hours * hour - minutes * minute) / second);
		int ms = (int)(totalMS - hours * hour - minutes * minute - seconds * second);
		
		String out = "";
		
		if (hours > 1) out += hours + " hours ";
		else if (hours == 1) out += "1 hour ";
		
		if (minutes > 1) out += minutes + " minutes ";
		else if (minutes == 1) out += "1 minute ";
		
		if (seconds > 1) out += seconds + " seconds ";
		else if (seconds == 1) out += "1 second ";
		
		if (ms > 0) out += ms + " ms ";
		
		out += "\t(" + totalMS + ")";
		
		return out;
	}
	

}
