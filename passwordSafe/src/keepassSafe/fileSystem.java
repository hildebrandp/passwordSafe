package keepassSafe;

import javacard.framework.*;

//Filesystem Class
//Creating/Writing/Reading and Deleting Files
public class fileSystem {
	
	//Create Arrays for Files
	private Object[] listFiles;
    private short[]  listfileSizes;
    private byte[] tempData;
    
    //Create NUmbers for Files
    public static final short keepassPW       = (short)0x0100;
    public static final short keepassFileName = (short)0x0101;
    public static final short keepassData1    = (short)0x0110;
    public static final short keepassData2    = (short)0x0111;
    private static final short keepassPW_Index      = (short)0x0000;
    private static final short keepassName_Index    = (short)0x0001;
    private static final short keepassData_Index1   = (short)0x0002;
    private static final short keepassData_Index2   = (short)0x0003;
    
	//Create Filesystem
	public fileSystem() {
		tempData = JCSystem.makeTransientByteArray((short)0x00FA, JCSystem.CLEAR_ON_DESELECT);
		listFiles = new Object[(short)4];
        listfileSizes = new short[(short)4];
	}
	
	//Method for Creating a File with specified size
	public void createFile(short fileID, short fileSize) {
		//Get Index of File
		short index = getFileIndex(fileID);
		
		//Check if File exists
		if(listFiles[index] == null) {
			//Create File
			listFiles[index] = new byte[fileSize];
		}
		
		//Add Filesize 
		listfileSizes[index] = fileSize;
	}
	
	//Method for deleting a File
	public void deleteFile(short fileID) {
		//Get Index of FIle
		short index = getFileIndex(fileID);
		
		//Check if File exists
		if(listFiles[index] != null) {
			//Delete File
			listFiles[index] = null;
		}
		
		//delete Filesize
		listfileSizes[index] = (short)0;
	}
	
	//Method for writing Data to File
	// fileID = ID of File
	// fileOffset = Offset where to write in File
	// fileData = Data which should be written
	// dataOffset = Offset of fileData
	// dataLength = Length of Data which should be written
	public void writeDataToFile(short fileID, short fileOffset, byte[] fileData, short dataOffset, short dataLength) {
		//Get max File size
		short selFileSize = getFileSize(fileID);

		//Check if File is full
        if (selFileSize < (short)(fileOffset + dataLength)) {
	        ISOException.throwIt(ISO7816.SW_FILE_FULL); 
        }
            
        //Write Data to File
        Util.arrayCopy(fileData, dataOffset, getFile(fileID), fileOffset, dataLength);
	}
	
	//Method for reading Data from File
	// fileID = ID for File
	// fileOffset = Offset where to start Reading
	// length = Length 
	public final byte[] readDataFromFile(short fileID, short fileOffset, short length) {
		//Get File size
		final short selFileSize = getFileSize(fileID);
		
		//Read Data From File and return Data
		Util.arrayCopyNonAtomic(getFile(fileID), fileOffset, tempData, (short)0, length);
		return (byte[])tempData;
	}
	
	//Method for getting the File Index Number
	private short getFileIndex(short fileID) {
		if(fileID == keepassData1) {
			return keepassData_Index1;
			
		} else if (fileID == keepassData2) {
			return keepassData_Index2;
			
		} else if (fileID == keepassPW) {
			return keepassPW_Index;
			
		} else if (fileID == keepassFileName) {
			return keepassName_Index;
			
		} else {
			return (short)-1;
		}
	}
	
	//Method for getting File
	private byte[] getFile(short fileID) {
		short index = getFileIndex(fileID);
		
		if(index == -1) {
			return null;
		}
		
		return (byte[]) listFiles[index];
	}
	
	//Method for getting File size
	public short getFileSize(short fileID) {
		short index = getFileIndex(fileID);
		
		if(index == (short)-1) {
			return (short)-1;
		}	
			
		return listfileSizes[index];
	}
}
