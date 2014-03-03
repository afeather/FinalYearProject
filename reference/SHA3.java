/*
Alex Feather
B119899

This is the SHA3 class. It extends the abstract class SHA which abstracts the reset, update and getHash
methods. The algorithm for this program is provided at ...

*/

public class SHA3 extends SHA {

	//this is the main method to hash something from the command line. If this program is called directly
	//then it will hash the first argument if there is only one or try to hash a file if there are 2 arguments
	//and the first one is "-f"
	public static void main(String[] args) {
		
		//create the SHA2 object
		SHA3 sha3 = new SHA3();
		
		//if there is only one argument then hasht the bytes from the string
		if (args.length == 1) sha3.update(args[0].getBytes());
		//if there are 2 arguments and one is "-f" then hash the bytes from the file
		else if (args.length == 2 && args[0] == "-f") sha3.update(args[1]);
		
		//extract the hash from the state and print it
		System.out.println(sha3.printHash());
		
	}
	
	//these constansts are provided by the Keccak specification
	private final long[] RC = new long[] {
		0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
		0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
		0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
		0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
		0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
		0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
		0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
		0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
	};
	
	private final int[] R = new int[] {
		0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43,
		25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14
	};
	
	//this is the length of the message digest. This can be adjusted but
	//32 was chosen to match the SHA2 program
	private final int length = 32;
	//this block length is obtained by (200 - 2 * length)
	private final int blockLength = 136;
	
	//this array stores the 5x5 word array that the keccak function
	//operates on. the state is stored as a 1d array where state[x][y]
	//would correspond to state[x + 5y]
	//state[0][0] = state[0]
	//state[1][0] = state[1]
	//state[0][1] = state[5]
	//state[1][1] = state[6]
	private long[] state;
	
	//this stores the bytes as they are given. the buffer is only processed when is is full
	private byte[] buffer = new byte[blockLength];
	private int bufferCount;
	
	//the constructor sets the variables to their initial values
	public SHA3() { reset(); }
	
	//this method sets all of the variables to teir initial state
	public void reset() {
		
		//create a new state
		this.state = new long[25];
		
		//empty the buffer
		bufferCount = 0;
		
	}
	
	//this method adds one byte to the buffer
	public void update(byte b) {
		
		//add the byte and increment the counter
		buffer[bufferCount++] = b;
		
		//if the buffer is full then process the buffer
		if (bufferCount == blockLength)
			processBuffer();
		
	}
	
	//this method processes the buffer and transforms the state
	private void processBuffer() {
		
		//for each 8 bytes in the buffer 
		for (int i = 0; i < blockLength; i += 8)
			//convert it to a little endian long
			//and xor it with the state
			state[i/8] ^= toLittle(buffer, i);
		
		//then we call the keccak function that transforms the state
		keccakf();
		
		//we need to empty the buffer
		bufferCount = 0;
		
	}
	
	//this method retrieves the hash values from the state
	public byte[] getHash() {
		
		//first we pad the message and fill the buffer
		addPadding();
		
		//then we process the buffer
		processBuffer();
		
		byte[] digest = new byte[length];
		
		//while our digest is not 32 bytes long
		for (int i = 0; i < length; i+=8) {
			
			//get a long from the state and convert it to a byte array
			byte[] temp = fromLittle(state[i/8]);
			
			//copy it to the digest array
			System.arraycopy(temp, 0, digest, i, 8);
			
		}
		
		//reset the hash to the default values
		reset();
		
		return digest;
		
	}
	
	//this method adds the padding to the message. The pading scheme is to append bit 1
	//and then bit 0 and then a final bit 1 (10*1)
	private void addPadding() {
		
		//if we only have one byte left we need to append 0b10000001
		if (bufferCount == blockLength - 1)
			buffer[135] = (byte) 0x81;
		
		//otherwise we need to pad with byte 0x00
		else {
			
			//append out bit 1 in little endian
			//0b00000001 -> 0b10000000
			buffer[bufferCount++] = (byte) 0x01;
			
			//while we have more than one byte open
			while (bufferCount < blockLength - 1)
				//append byte 0x00
				buffer[bufferCount++] = (byte) 0x00;
			
			//append final bit 1
			//0b10000000 -> 0b00000001
			buffer[135] = (byte) 0x80;
			
		}
		
	}
	
	//this is the keccak function. This method is responsible for manipulating the state
	//to produce the hash values.
	private void keccakf() {
		
		//we initialize some variables
		long[] B, C, D;
		
		//much of this is from the Keccak documentation. This code will be explained in the report.
		for (int round = 0; round < 24; round++) {
		
			B = new long[25];
			C = new long[5];
			D = new long[5];
			
			for (int i = 0; i < 5; i++) 
				C[i] = state[index(i,0)] ^ state[index(i,1)] 
					 ^ state[index(i,2)] ^ state[index(i,3)] 
					 ^ state[index(i,4)];
			
			for (int i = 0; i < 5; i++) {
				
				D[i] =   C[index(i-1)] 
					 ^ ((C[index(i+1)] << 1) | (C[index(i+1)] >>> (64 - 1)));
				
				for (int j = 0; j < 5; j++) 
					state[index(i, j)] ^= D[i];
				
			}
			
			for (int i = 0; i < 5; i++) 
				for (int j = 0; j < 5; j++) 
					B[index(j, i * 2 + 3 * j)] = ((state[index(i,j)] << R[index(i,j)]) 
					| (state[index(i,j)] >>> (64 - R[index(i,j)])));
				
			for (int i = 0; i < 5; i++) 
				for (int j = 0; j < 5; j++) 
					state[index(i,j)] = B[index(i,j)] ^ (~B[index(i+1, j)] 
									  & B[index(i+2, j)]);
			
			state[0] ^= RC[round];
			
		}
		
	}
	
	//this helper method converts a byte array to a long in little endian
	private long toLittle(byte[] bytes, int index) {
		
		//bytes[] = 0xAA 0xBB 0x00 0x00 0x00 0x00 0x00 0x00
		//0xAA -> bitmask 0xFF -> 0xAA -> to long -> 0x00000000000000AA -> shift 0 -> 0x00000000000000AA
		//0xBB -> bitmask 0xFF -> 0xBB -> to long -> 0x00000000000000BB -> shift 8 -> 0x000000000000BB00
		//																		   -> 0x000000000000BBAA
		return    (long) (bytes[index    ] & 0xFF)
				| (long) (bytes[index + 1] & 0xFF) << 8
				| (long) (bytes[index + 2] & 0xFF) << 16
				| (long) (bytes[index + 3] & 0xFF) << 24
				| (long) (bytes[index + 4] & 0xFF) << 32
				| (long) (bytes[index + 5] & 0xFF) << 40
				| (long) (bytes[index + 6] & 0xFF) << 48
				| (long) (bytes[index + 7] & 0xFF) << 56;
		
	}
	
	//this helper method creates a byte array from a long in little endian
	private byte[] fromLittle(long n) {
		
		byte[] out = new byte[8];
		
		//0xAABBCCDDEEFFGGHH
		//out[0] = 0xAABBCCDDEEFFGGHH -> shift 0 -> 0xAABBCCDDEEFFGGHH -> to byte -> 0xHH
		//out[1] = 0xAABBCCDDEEFFGGHH -> shift 8 -> 0x00AABBCCDDEEFFGG -> to byte -> 0xGG
		out[0] = (byte)  n        ;
		out[1] = (byte) (n >>> 8 );
		out[2] = (byte) (n >>> 16);
		out[3] = (byte) (n >>> 24);
		out[4] = (byte) (n >>> 32);
		out[5] = (byte) (n >>> 40);
		out[6] = (byte) (n >>> 48);
		out[7] = (byte) (n >>> 56);
		
		return out;
	}
	
	//these helper methods make sure we are referencing the right elements of the state
	private final int index(int a)        { return ( a + 5 ) % 5; }
	private final int index(int a, int b) { return index( a ) + ( 5 * index( b )); }
	
}
