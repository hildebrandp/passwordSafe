package keepassSafe;

import javacard.framework.*;
import javacard.security.RandomData;

public class passwordSafe extends Applet
{
	final static byte CLA_NUMBER = (byte) 0x80;
    
	final static byte INS_INIT       = (byte) 0x20;
	final static byte INS_PIN_VERIFY = (byte) 0x21;
	final static byte INS_CHANGE_PIN = (byte) 0x22;
	final static byte INS_PIN_RESET  = (byte) 0x23;
	
	final static byte INS_PW_SET  = (byte) 0x30;
	final static byte INS_PW_GET  = (byte) 0x31;
	final static byte INS_PW_DEL  = (byte) 0x32;
	
	final static byte INS_CREATE_FILE   = (byte) 0xE0;
    final static byte INS_UPDATE_BINARY = (byte) 0xD6;
    final static byte INS_READ_BINARY   = (byte) 0xB0;
    final static byte INS_DELETE_FILE   = (byte) 0xE4;
        
    //Variables for the PIN
    private final static byte PIN_MAX_TRIES  = (byte) 3;
    private final static byte PIN_MIN_LENGTH = (byte) 2;
    private final static byte PIN_MAX_LENGTH = (byte) 16;
    //Variables for the PUK
    private final static byte PUK_MAX_TRIES = (byte) 3;
    private final static byte PUK_LENGTH    = (byte) 6;
    
    private static final byte STATE_INIT           = (byte) 0x00; 
    private static final byte STATE_SECURE_NO_DATA = (byte) 0x01; 
    private static final byte STATE_SECURE_DATA    = (byte) 0x02; 
    
    private static final byte MASTER_PW_STORED_YES   = (byte) 0x01; 
    private static final byte MASTER_PW_STORED_NO    = (byte) 0x02; 
    
    // Status words:
    public static final short SW_PIN_TRIES_REMAINING = (short)0x63C0;
    public static final short SW_COMMAND_NOT_ALLOWED_GENERAL = (short)0x6900;
    
    private byte state;
    private byte masterPW;
    private byte masterPWlength;
    private OwnerPIN pin = null;
    private OwnerPIN puk = null;
	private RandomData randomKey;
	private fileSystem myfile;


	public static void install(byte[] buffer, short offset, byte length) {
        new passwordSafe(); 
    } 
    
    private passwordSafe() {
    	
	    pin = new OwnerPIN(PIN_MAX_TRIES, PIN_MAX_LENGTH);
        puk = new OwnerPIN(PUK_MAX_TRIES, PUK_LENGTH);
		
		//Set state
        state = STATE_INIT;
        masterPW = MASTER_PW_STORED_NO;
        masterPWlength = (byte)0;
        
        myfile = new fileSystem();
        
        randomKey = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        
        register(); 
    }

    public void deselect() { 
        pin.reset();
        puk.reset();
    }

	public void process(APDU apdu) {
		
		byte buffer[] = apdu.getBuffer();
		byte cla = buffer[ISO7816.OFFSET_CLA];
        byte ins = buffer[ISO7816.OFFSET_INS];
        
        if(selectingApplet()) {
			buffer[0] = state;
            apdu.setOutgoingAndSend((short) 0, (short) 1);
			return;
        }
        
        if(cla == CLA_NUMBER) {
        	
	        switch (ins) {
	        	//Personal Data
	        	//INS = 0x20
				case INS_INIT:
					cardINIT(apdu);
					break;
				//INS = 0x21
				case INS_PIN_VERIFY:
					checkPIN(apdu);
					break;	
				//INS = 0x22	
				case INS_CHANGE_PIN:
					changePIN(apdu);
					break;
				//INS = 0x23
				case INS_PIN_RESET:
					resetPIN(apdu);
					break;
					
				//Master Password
				//INS = 0x30
				case INS_PW_SET:
					setMasterPW(apdu);
					break;
				//INS = 0x31
				case INS_PW_GET:
					getMasterPW(apdu);
					break;
				//INS = 0x32
				case INS_PW_DEL:
					delMasterPW(apdu);
					break;
						
				//Data Storage
				//INS = 0xE0
				case INS_CREATE_FILE:
					createFile(apdu);
					break;
				//INS = 0xD6
				case INS_UPDATE_BINARY:
					writeFile(apdu);
					break;
				//INS = 0xB0
				case INS_READ_BINARY:
					readFile(apdu);
					break;
				//INS = 0xE4
				case INS_DELETE_FILE:
					deleteFile(apdu);
					break;
					
				default:
					ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
	        }
	        
        } else {
        	
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
	}
	
	//CLA = 0x80; INS = 0x20; P1 = 0x00; P2 = 0x01
	private void cardINIT(APDU apdu) throws ISOException {
		byte[] buf = apdu.getBuffer();
		byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short offset_cdata;
        short lc;
        
        //Check lenght field
        lc = apdu.setIncomingAndReceive();
        if(lc != apdu.getIncomingLength()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        //Get the Offset of the Data
        offset_cdata = apdu.getOffsetCdata();
        //Check if the State is correct
        if(state != STATE_INIT) {
	        ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
        
        if(p1 != (byte)0x00 && p2 != (byte)0x01) {
	        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        
        if(lc > PIN_MAX_LENGTH || lc < PIN_MIN_LENGTH) {
	        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        Util.arrayFillNonAtomic(buf, (short)(offset_cdata + lc), (short)(PIN_MAX_LENGTH - lc), (byte) 0x00);
        pin.update(buf, offset_cdata, PIN_MAX_LENGTH);
        pin.resetAndUnblock();
        
        
        randomKey.generateData(buf, (short) 0, PUK_LENGTH);
	
		puk.update(buf, (short)0, PUK_LENGTH);
		puk.resetAndUnblock();
		
		state = STATE_SECURE_NO_DATA;
		
        apdu.setOutgoingAndSend((short) 0, PUK_LENGTH); 
	}
	
	//Verify PIN
	//CLA = 0x80; INS = 0x21; P1 = 0x01; P2 = 0x00; Data = PIN
	private void checkPIN(APDU apdu) throws ISOException {
		byte[] buf = apdu.getBuffer();
		byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short offset_cdata;
        short lc;
        
        //Check lenght field
        lc = apdu.setIncomingAndReceive();
        if(lc != apdu.getIncomingLength()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        //Get the Offset of the Data
        offset_cdata = apdu.getOffsetCdata();
        //Check if the State is correct
        if(state == STATE_INIT) {
	        ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
        
        if(p1 != (byte)0x01 && p2 != (byte)0x00) {
	        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        
        Util.arrayFillNonAtomic(buf, (short)(offset_cdata + lc), (short)(PIN_MAX_LENGTH - lc), (byte) 0x00);
        
        if(! pin.check(buf, offset_cdata, PIN_MAX_LENGTH)) {
	        ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
        } else {
	        buf[0] = masterPW;
			apdu.setOutgoingAndSend((short) 0, (short) 1);
        }
        
	}

	//Change PIN 
	//CLA = 0x80; INS = 0x22; P1 = 0x00; P2 = 0x02;Data = OLD_PIN + NEW_PIN
	//Musst be padded, new Pin legth check at phone
	private void changePIN(APDU apdu) throws ISOException {
		byte[] buf = apdu.getBuffer();
		byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short offset_cdata;
        short lc;
        
        if(! pin.isValidated()){
	        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        
        //Check lenght field
        lc = apdu.setIncomingAndReceive();
        if(lc != apdu.getIncomingLength()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        //Get the Offset of the Data
        offset_cdata = apdu.getOffsetCdata();
        
        if(p1 != (byte)0x00 && p2 != (byte)0x02) {
	        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        
        if(lc != (short)(2*PIN_MAX_LENGTH)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        if(! pin.check(buf, offset_cdata, PIN_MAX_LENGTH)) {
	        ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | puk.getTriesRemaining()));
        }
        
        if( (byte)(lc - PUK_LENGTH) < PIN_MIN_LENGTH || (byte)(lc - PUK_LENGTH) > PIN_MAX_LENGTH) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
        
        pin.update(buf, (short)(offset_cdata + PIN_MAX_LENGTH), PIN_MAX_LENGTH);
        
	}

	//Reset PIN
	//CLA = 0x80; INS = 23; P1 = 0x01; P2 = 02; Data = PUK + PIN 
	private void resetPIN(APDU apdu) throws ISOException {
		byte[] buf = apdu.getBuffer();
		byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short offset_cdata;
        short lc;
        
        if(! (pin.getTriesRemaining() == 0)) {
	        ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
        }
        
        //Check lenght field
        lc = apdu.setIncomingAndReceive();
        if(lc != apdu.getIncomingLength()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        //Get the Offset of the Data
        offset_cdata = apdu.getOffsetCdata();
        //Check if the State is correct
        if(state == STATE_INIT) {
	        ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
        
        if(p1 != (byte)0x01 && p2 != (byte)0x02) {
	        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        
        if(! puk.check(buf, offset_cdata, PUK_LENGTH)) {
	        ISOException.throwIt((short)(SW_PIN_TRIES_REMAINING | puk.getTriesRemaining()));
        }
        
        if( (byte)(lc - PUK_LENGTH) < PIN_MIN_LENGTH || (byte)(lc - PUK_LENGTH) > PIN_MAX_LENGTH) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		
		Util.arrayFillNonAtomic(buf, (short)(offset_cdata + PUK_LENGTH + (lc - PUK_LENGTH)), (short)(PIN_MAX_LENGTH - (lc - PUK_LENGTH)), (byte) 0x00);
        
        pin.update(buf, (short)(offset_cdata + PUK_LENGTH), PIN_MAX_LENGTH);
	}

	private void setMasterPW(APDU apdu) throws ISOException {
		byte[] buf = apdu.getBuffer();
		byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short offset_cdata;
        short lc;
        
        if(! pin.isValidated()) {
	        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        
        //Check lenght field
        lc = apdu.setIncomingAndReceive();
        if(lc != apdu.getIncomingLength()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        //Get the Offset of the Data
        offset_cdata = apdu.getOffsetCdata();
        //Check if the State is correct
        if(state == STATE_INIT || masterPW == MASTER_PW_STORED_YES) {
	        ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
        
        if(p1 != (byte)0x02 && p2 != (byte)0x01) {
	        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        
        myfile.createFile(myfile.keepassPW, lc);
        myfile.writeDataToFile(myfile.keepassPW, (short)0, buf, offset_cdata, lc);
        
        masterPWlength = (byte)(lc & 0xff);
        masterPW = MASTER_PW_STORED_YES;
	}

	private void getMasterPW(APDU apdu) throws ISOException {
		byte[] buf = apdu.getBuffer();
		byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short offset_cdata;
        short lc;
        
        if(! pin.isValidated()) {
	        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        
        //Check lenght field
        lc = apdu.setIncomingAndReceive();
        if(lc != apdu.getIncomingLength()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        //Get the Offset of the Data
        offset_cdata = apdu.getOffsetCdata();
        //Check if the State is correct
        if(state == STATE_INIT || masterPW == MASTER_PW_STORED_NO) {
	        ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
        
        if(p1 != (byte)0x02 && p2 != (byte)0x02) {
	        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        
        byte[] tmp = myfile.readDataFromFile(myfile.keepassPW, (short)0, masterPWlength);
        Util.arrayCopy(tmp, (short)0, buf, (short)0, masterPWlength);
        apdu.setOutgoingAndSend((short) 0, masterPWlength); 
	}

	private void delMasterPW(APDU apdu) throws ISOException {
		byte[] buf = apdu.getBuffer();
		byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short offset_cdata;
        short lc;
        
        if(! pin.isValidated()) {
	        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        
        //Check lenght field
        lc = apdu.setIncomingAndReceive();
        if(lc != apdu.getIncomingLength()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        //Get the Offset of the Data
        offset_cdata = apdu.getOffsetCdata();
        //Check if the State is correct
        if(state == STATE_INIT || masterPW == MASTER_PW_STORED_NO) {
	        ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
        
        if(p1 != (byte)0x02 && p2 != (byte)0x03) {
	        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        
        myfile.deleteFile(myfile.keepassPW);
        masterPW = MASTER_PW_STORED_NO;
        masterPWlength = (byte)0;
	}

	private void createFile(APDU apdu) throws ISOException {
		
		state = STATE_SECURE_DATA;
	}
	
	private void writeFile(APDU apdu) throws ISOException {
		
		if(state != STATE_SECURE_DATA) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
	}
	
	private void readFile(APDU apdu) throws ISOException {
		
		if(state != STATE_SECURE_DATA) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
	}
	
	private void deleteFile(APDU apdu) throws ISOException {
		
		if(state != STATE_SECURE_DATA) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		} else {
			state = STATE_SECURE_NO_DATA;
		}
		
	}
}
