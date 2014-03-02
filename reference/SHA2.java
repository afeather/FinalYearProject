/*
Alex Feather
B119899

This is the SHA2 class. It extends the abstract class SHA which abstracts the reset, update and getHash
methods. The algorithm for this program is provided at ...

*/
public class SHA2 extends SHA {
	
	//this is the main method to hash something from the command line. If this program is called directly
	//then it will hash the first argument if there is only one or try to hash a file if there are 2 arguments
	//and the first one is "-f"
	public static void main(String[] args) { 
		
		//create the SHA2 object
		SHA2 sha2 = new SHA2();
		
		//if there is only one argument then hasht the bytes from the string
		if (args.length == 1) sha2.update(args[0].getBytes());
		//if there are 2 arguments and one is "-f" then hash the bytes from the file
		else if (args.length == 2 && args[0] == "-f") sha2.update(args[1]);
		
		//extract the hash from the state and print it
		System.out.println(sha2.printHash());
	}
	
	//These constants are provided by the NIST specification
	private final int[] k = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};
	
	//this will store out hash values
	private int[] hash = new int[8];
	//we need to represent out message length as 64 bits when we pad the message
	private long  messageLength;
	
	//this stores the bytes as they are given. The buffer is only processed when it is full
	private byte[] buffer = new byte[64];
	private int bufferCount;
	
	//the constructor sets the variables to their initial values
	public SHA2() { reset(); }

	//this method adds bytes to the buffer
	public void update(byte b) {
		
		//we add the byte and increment the counter
		buffer[bufferCount++] = b;
		//we also need to increment the message length
		messageLength += 8;
		
		//if the buffer is full then process the buffer
		if (bufferCount == 64) processBuffer();
		
	}
	
	//this method processes the buffer and transforms the hash values
	private void processBuffer() {
		
		//first we need to convert the buffer to 32 bit words. Java uses 32 bits for integers
		int[] bufferToInt = convertBuffer(buffer);
		//then initialize the working values
		int[] w = new int[64];
		
		//copy the buffer into the working values
		System.arraycopy(bufferToInt, 0, w, 0, 16);
		
		//extend the 16 values into all 64 words
		w = extend(w);
		
		//compress the 64 words into the 8 hash words
		compress(w);
		
		//reset the buffer count
		bufferCount = 0;
		
	}
	
	//this metheod converts our byte array buffer into an int array
	private int[] convertBuffer(byte[] b) {
		
		//each integer will use 4 bytes
		int[] integers = new int[b.length/4];
		
		//for every 4 bytes
		for (int i = 0; i < b.length; i+=4) 
		
			//convert the bytes to ints, shift them to the appropriate position
			//and 'or' them together. 
			//0xAA -> to int -> 0x000000AA -> shift 8 -> 0x0000AA00
			//0xBB -> to int -> 0x000000BB -> shift 0 -> 0x000000BB
			//											 0x0000AABB
			integers[i/4] = (int) (b[i] & 0xFF) << 24 
					| (int) (b[i+1] & 0xFF) << 16 
					| (int) (b[i+2] & 0xFF) << 8 
					| (int) (b[i+3] & 0xFF);
		
		return integers;
		
	}
	
	//this method extends out working array
	private int[] extend(int[] w){
		
		//initialize temp variables
		int temp1, temp2;
		
		//This code will be explained in the report. These formula come from the SHA2 specification.
		for (int i = 16; i < 64; i++) {
			
			temp1 = (Integer.rotateRight(w[i-15], 7)) ^ (Integer.rotateRight(w[i-15], 18)) ^ (w[i-15] >>> 3 );
			temp2 = (Integer.rotateRight(w[i-2], 17)) ^ (Integer.rotateRight(w[i-2 ], 19)) ^ (w[i-2 ] >>> 10);
			
			w[i] = w[i-16] + temp1 + w[i-7] + temp2;
			
		}
		
		return w;
	}
	
	//this method compresses our working array
	private void compress(int[] w) {
		
		//initialize temp variables
		int[] temp = new int[8];
		
		//intialize variables to store function results
		int s1, ch, temp1, s0, maj, temp2;
		
		//copy the hash values to the temp array
		for (int i = 0; i < 8; i++) temp[i] = hash[i];
		
		//this code will be explained in the report. The formula come from the SHA2 specification.
		for (int i = 0; i < 64; i++) {
			
			s1 = (Integer.rotateRight(temp[4], 6)) ^ (Integer.rotateRight(temp[4], 11)) ^ (Integer.rotateRight(temp[4], 25));
			ch = (temp[4] & temp[5]) ^ ((~temp[4]) & temp[6]);
			temp1 = temp[7] + s1 + ch + k[i] + w[i];
			s0 = (Integer.rotateRight(temp[0], 2)) ^ (Integer.rotateRight(temp[0], 13)) ^ (Integer.rotateRight(temp[0], 22));
			maj = (temp[0] & temp[1]) ^ (temp[0] & temp[2]) ^ (temp[1] & temp[2]);
			temp2 = s0 + maj;
			
			temp[7] = temp[6];
			temp[6] = temp[5];
			temp[5] = temp[4];
			temp[4] = (temp[3] + temp1) & 0xFFFFFFFF;
			temp[3] = temp[2];
			temp[2] = temp[1];
			temp[1] = temp[0];
			temp[0] = (temp1   + temp2) & 0xFFFFFFFF;
					
		}
		
		for (int i = 0; i < 8; i++) hash[i] = (hash[i] + temp[i]) & 0xFFFFFFFF;
		
	}

	//this method converts the int array to a byte array
	public byte[] getHash() {
		
		//first we pad the message and fill the buffer
		addPadding();
		
		//then we process the buffer
		processBuffer();
		
		byte[] digest = new byte[32];
		
		//for each integer
		for (int i = 0; i < 8; i++) {
			
			int nextInt = hash[i];
			
			//we shift the bits down and use a bitmask to get only the bits we need
			//0x0000AABB -> shift 8 -> 0x000000AA -> bitmask 0xFF -> 0x000000AA -> to byte -> 0xAA
			//0x0000AABB -> shift 0 -> 0x0000AABB -> bitmask 0xFF -> 0x000000BB -> to byte -> 0xBB
			digest[i*4    ] = (byte) ((nextInt >>> 24) & 0xFF);
			digest[i*4 + 1] = (byte) ((nextInt >>> 16) & 0xFF);
			digest[i*4 + 2] = (byte) ((nextInt >>>  8) & 0xFF);
			digest[i*4 + 3] = (byte) ((nextInt       ) & 0xFF);
			
		}
		
		//we must reset the hash values before more data is hashed
		reset();
		
		return digest;
		
	}

	//This method adds the padding to the message. The padding scheme is to append bit 1 and then bit 0
	//until there are only 64 bits remaining in the block. Then we append the message length as 64 bits
	private void addPadding() {
		
		//append byte 0x80 or 0b100000000
		buffer[bufferCount++] = (byte) 0x80;
		
		//if there is less than 64 bits left
		if (bufferCount > 56) {
			
			//fill the buffer with 0x00
			while (bufferCount < 64) buffer[bufferCount++] = (byte) 0x00;
			
			//process the buffer and reset the buffer count
			processBuffer();
			
		}		
		
		//while there are more then 64 bits left append byte 0x00
		while (bufferCount < 56) buffer[bufferCount++] = (byte) 0x00;
		
		//append the Long message length to the byte array
		buffer[56] = (byte)(messageLength >>> 56);
		buffer[57] = (byte)(messageLength >>> 48);
		buffer[58] = (byte)(messageLength >>> 40);
		buffer[59] = (byte)(messageLength >>> 32);
		buffer[60] = (byte)(messageLength >>> 24);
		buffer[61] = (byte)(messageLength >>> 16);
		buffer[62] = (byte)(messageLength >>> 8 );
		buffer[63] = (byte)(messageLength       );
		
	}
	
	//set the hash values to their intial values
	public void reset() {
		
		//these are given in the SHA2 specification
		hash[0] = 0x6a09e667;
		hash[1] = 0xbb67ae85;
		hash[2] = 0x3c6ef372;
		hash[3] = 0xa54ff53a;
		hash[4] = 0x510e527f;
		hash[5] = 0x9b05688c;
		hash[6] = 0x1f83d9ab;
		hash[7] = 0x5be0cd19;
		
		messageLength = 0;
		bufferCount = 0;
		
	}

}