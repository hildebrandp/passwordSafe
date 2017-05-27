package keepassSafe;


import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class fileSystem {
	
	private Object[] listFiles;
    private short[]  listfileSizes;
    
    public static final short keepassPW    = (short)0x0100;
    public static final short keepassData1 = (short)0x0101;
    public static final short keepassData2 = (short)0x0102;
    private static final short keepassPW_Index    = (short)0x0001;
    private static final short keepassData_Index1 = (short)0x0002;
    private static final short keepassData_Index2 = (short)0x0003;
    
	
	public fileSystem() {
		listFiles = new Object[(short)3];
        listfileSizes = new short[(short)3];
	}
	
	public void createFile(short fileID, short fileSize) {
		short index = getFileIndex(fileID);
		
		if(listFiles[index] == null) {
			listFiles[index] = new byte[fileSize];
		}
		
		listfileSizes[index] = fileSize;
	}
	
	public void deleteFile(short fileID) {
		short index = getFileIndex(fileID);
		
		if(listFiles[index] != null) {
			listFiles[index] = null;
		}
		
		listfileSizes[index] = (short)0;
	}
	
	public void writeDataToFile(short fileID, short fileOffset, byte[] fileData, short dataOffset, short dataLength) {
		
		short selFileSize = getFileSize(fileID);

        if (selFileSize < (short)(fileOffset + dataLength)) {
	        ISOException.throwIt(ISO7816.SW_FILE_FULL); 
        }
            
        Util.arrayCopy(fileData, dataOffset, getFile(fileID), fileOffset, dataLength);
	}
	
	public byte[] readDataFromFile(short fileID, short fileOffset, short length) {
		
		short selFileSize = getFileSize(fileID);
		byte[] data = new byte[length];
		
		if((short)(fileOffset + length) > selFileSize) {
			Util.arrayCopy(getFile(fileID), fileOffset, data, (short)0, (short)(selFileSize - fileOffset));
		} else {
			Util.arrayCopy(getFile(fileID), fileOffset, data, (short)0, length);
		}
		
		return (byte[])data;
	}
	
	private short getFileIndex(short fileID) {
		if(fileID == keepassData1) {
			return keepassData_Index1;
			
		} else if (fileID == keepassData2) {
			return keepassData_Index2;
			
		} else if (fileID == keepassPW) {
			return keepassPW_Index;
			
		} else {
			return (short)-1;
		}
	}
	
	private byte[] getFile(short fileID) {
		short index = getFileIndex(fileID);
		
		if(index == -1) {
			return null;
		}
		
		return (byte[]) listFiles[index];
	}
	
	private short getFileSize(short fileID) {
		short index = getFileIndex(fileID);
		
		if(index == (short)-1) {
			return (short)-1;
		}
		
		return listfileSizes[index];
	}
}
