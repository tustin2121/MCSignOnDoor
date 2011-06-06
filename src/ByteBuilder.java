/*****************************************

This class specifically is released into the 
Public Domain by the creator, Tustin2121.
Feel free to use it however you please.

*****************************************/

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.util.Arrays;

public class ByteBuilder {
	private byte[] array;
	private int size;
	
	public ByteBuilder() {
		this(10);
	}
	public ByteBuilder(int capacity) {
		array = new byte[capacity];
		size = 0;
	}
	
	public ByteBuilder(byte[] array){
		this.array = Arrays.copyOf(array, array.length*2);
		size = array.length;
	}
	
	public void ensureCapacity(int capacity){
		if (capacity > this.array.length){
			this.array = Arrays.copyOf(array, capacity);
		}
	}
	
	private void testAddition(int addition){
		while (size+addition >= this.array.length){
			this.array = Arrays.copyOf(array, this.array.length*2);
		}
	}
	
	private void copyIntoArray(byte[] b){
		for (int i = 0; i < b.length; i++) {
            array[size+i] = b[i];
        }
		size += b.length;
	}
	
	public int capacity(){ return array.length; }
	public int size(){ return size; }
	
	public void truncate(int size) {
		array = Arrays.copyOf(array, size);
	}
	
	public byte[] subSequence(int start, int end){
		return Arrays.copyOfRange(array, start, end);
	}
	
	public byte[] toByteArray(){
		return Arrays.copyOf(array, size);
	}
	
	@Override public String toString() {
		return new String(Arrays.copyOf(array, size));
	}
	
	//all append() methods return this so we can chain calls together, of course :)
	
	public ByteBuilder append(byte value){
		testAddition(1);
		this.array[size++] = value;
		return this; 
	}
	public ByteBuilder append(byte[] value){
		return this.append(value, 0, value.length);
	}
	public ByteBuilder append(byte[] value, final int offset, final int len){
		if (offset+len > value.length) throw new ArrayIndexOutOfBoundsException();
		
		testAddition(len);
		for (int i = 0; i < len; i++){
//			System.out.println("Size:"+size+" i:"+i+" len:"+len+" offset:"+offset);
			this.array[size+(i)] = value[i+offset];
		}
		size += len;
		return this; 
	}
	/*
	public ByteBuilder append(char value){
		testAddition(1);
		this.array[size++] = (byte)value;
		return this; 
	}
	public ByteBuilder append(char[] value){
		return this.append(value, 0, value.length);
	}
	public ByteBuilder append(char[] value, final int offset, final int len){
		if (offset+len > value.length) throw new ArrayIndexOutOfBoundsException();
		
		testAddition(len);
		for (int i = 0; i < len; i++){
			this.array[size+(i)] = (byte)value[i+offset];
		}
		size += len;
		return this; 
	}
	//*/
	//*
 	public ByteBuilder append(char value){
		final int LEN = 2; //char are 2 bytes long
		testAddition(LEN);
		{
			byte[] b = new byte[LEN];
	        for (int i = 0; i < LEN; i++) {
	            int offset = (b.length - 1 - i) * 8;
	            b[i] = (byte) ((value >>> offset) & 0xFF);
	        }
	        System.out.printf("%x%x\n", b[0], b[1]);
	        copyIntoArray(b);
		}
		return this; 
	}
	public ByteBuilder append(char[] value){
		return this.append(value, 0, value.length);
	}
	public ByteBuilder append(char[] value, final int offset, final int len){
		if (offset+len > value.length) throw new ArrayIndexOutOfBoundsException();
		
		for (int i = offset; i < offset+len; i++){
			this.append(value[i]);
		}
		
		return this; 
	}
	//*/
	
	public ByteBuilder append(boolean value){
		testAddition(1);
		this.array[size++] = (byte) ((value)?1:0);
		return this; 
	}
	
	public ByteBuilder append(int value){
		final int LEN = 4; //char are 4 bytes long
		testAddition(LEN);
		{
			byte[] b = new byte[LEN];
	        for (int i = 0; i < LEN; i++) {
	            int offset = (b.length - 1 - i) * 8;
	            b[i] = (byte) ((value >>> offset) & 0xFF);
	        }
	        
	        copyIntoArray(b);
		}
		return this; 
	}
	
	public ByteBuilder append(long value){
		final int LEN = 8; //char are 8 bytes long
		testAddition(LEN);
		{
			byte[] b = new byte[LEN];
	        for (int i = 0; i < LEN; i++) {
	            int offset = (b.length - 1 - i) * 8;
	            b[i] = (byte) ((value >>> offset) & 0xFF);
	        }
	        
	        copyIntoArray(b);
		}
		return this; 
	}
	
	public ByteBuilder append(float value){
		final int LEN = 8; //char are 8 bytes long
		testAddition(LEN);
		int intval = Float.floatToRawIntBits(value);
		{
			byte[] b = new byte[LEN];
	        for (int i = 0; i < LEN; i++) {
	            int offset = (b.length - 1 - i) * 8;
	            b[i] = (byte) ((intval >>> offset) & 0xFF);
	        }
	        
	        copyIntoArray(b);
		}
		return this; 
	}
	
	public ByteBuilder append(double value){
		final int LEN = 8; //char are 8 bytes long
		testAddition(LEN);
		long intval = Double.doubleToRawLongBits(value);
		{
			byte[] b = new byte[LEN];
	        for (int i = 0; i < LEN; i++) {
	            int offset = (b.length - 1 - i) * 8;
	            b[i] = (byte) ((intval >>> offset) & 0xFF);
	        }
	        
	        copyIntoArray(b);
		}
		return this; 
	}
	
	public ByteBuilder append(Object value){
		try {
			//attempts to call a toByteStructure() method on the object, if it has it.
			Method bytem = value.getClass().getMethod("toByteStructure", (Class<?>[])null);
			byte[] array = (byte[]) bytem.invoke(value);
			return this.append(array);
		} 
		catch (SecurityException e) { e.printStackTrace(); } //shouldn't happen 
		catch (IllegalArgumentException e) { e.printStackTrace(); } //shouldn't happen 
		catch (IllegalAccessException e) { e.printStackTrace(); } //shouldn't happen 
		catch (InvocationTargetException e) { e.printStackTrace(); } //shouldn't happen 
		catch (NoSuchMethodException e) { } //will happen, a lot
		
		//if the above did not work, instead append the result of the toString() method.
		return this.append(value.toString());
	}
	
	public ByteBuilder append(String value){
//		byte[] b = value.getBytes(Charset.defaultCharset());
//		try {
//			b = value.getBytes("UTF8");
//		} catch (UnsupportedEncodingException e) {
//			throw new RuntimeException("Error encoding string!");
//		}
//		System.out.println(Arrays.toString(b));
//		System.out.println();
//		testAddition(b.length);
//		return this.append(b);
		//*/
/*		try {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			DataOutputStream dos = new DataOutputStream(baos);
			dos.writeUTF(value);
			dos.close();
			byte[] b = baos.toByteArray();
			System.out.println(Arrays.toString(b));
			testAddition(b.length);
			return this.append(b);
		} catch (IOException e){
			throw new RuntimeException("Error encoding string!");
		}//*/
		try {
			CharBuffer cb = CharBuffer.wrap(value);
			CharsetEncoder e = Charset.forName("UTF-16BE").newEncoder();
			ByteBuffer bb = e.encode(cb);
			testAddition(bb.position());
			bb.rewind();
			byte[] b = new byte[bb.remaining()];
			bb.get(b);
//			System.out.println(Arrays.toString(b));
			return this.append(b);
		} catch (IOException e){
			throw new RuntimeException("Error encoding string!");
		}
	}
	
	public ByteBuilder append(StringBuffer value){
		byte[] b = value.toString().getBytes(Charset.defaultCharset());
		testAddition(b.length);
		return this.append(b);
	}
	
	///////// and now, appendSpecial() //////////
	
	public ByteBuilder appendSpecial(long value, int length, boolean preserveNegative){
		testAddition(length);
		{
			byte[] b = new byte[length];
	        for (int i = 0; i < length; i++) {
	            int offset = (b.length - 1 - i) * 8;
	            b[i] = (byte) ((value >>> offset) & 0xFF);
	            if (preserveNegative && i == 0){
	            	if (value < 0){ //original value is negative
	            		b[i] |= 0x80; // 1000 0000 - or'ed into the value to make it negative
	            	} else { //original value is positive
	            		b[i] &= 0x7F; // 0111 0000 - and'ed into the value to clear the negative bit
	            	}
	            }
	        }
	        
	        copyIntoArray(b);
		}
		
		return this;
	}
}
