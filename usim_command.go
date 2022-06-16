package usim_go

import "errors"

var (
	/* See ETSI GSM 11.11 and ETSI TS 102 221 for details.
	 * SIM commands:
	 * Command APDU: CLA INS P1 P2 P3 Data
	 *   CLA (class of instruction): A0 for GSM, 00 for USIM
	 *   INS (instruction)
	 *   P1 P2 P3 (parameters, P3 = length of Data)
	 * Response APDU: Data SW1 SW2
	 *   SW1 SW2 (Status words)
	 * Commands (INS P1 P2 P3):
	 *   SELECT: A4 00 00 02 <file_id, 2 bytes>
	 *   GET RESPONSE: C0 00 00 <len>
	 *   RUN GSM ALG: 88 00 00 00 <RAND len = 10>
	 *   RUN UMTS ALG: 88 00 81 <len=0x22> data: 0x10 | RAND | 0x10 | AUTN
	 *	P1 = ID of alg in card
	 *	P2 = ID of secret key
	 *   READ BINARY: B0 <offset high> <offset low> <len>
	 *   READ RECORD: B2 <record number> <mode> <len>
	 *	P2 (mode) = '02' (next record), '03' (previous record),
	 *		    '04' (absolute mode)
	 *   VERIFY CHV: 20 00 <CHV number> 08
	 *   CHANGE CHV: 24 00 <CHV number> 10
	 *   DISABLE CHV: 26 00 01 08
	 *   ENABLE CHV: 28 00 01 08
	 *   UNBLOCK CHV: 2C 00 <00=CHV1, 02=CHV2> 10
	 *   SLEEP: FA 00 00 00
	 */

	SCARD_USIM    = 1
	SCARD_GSM_SIM = 2
	/* GSM SIM commands */
	SIM_CMD_SELECT       = []byte{0xa0, 0xa4, 0x00, 0x00, 0x02}
	SIM_CMD_RUN_GSM_ALG  = []byte{0xa0, 0x88, 0x00, 0x00, 0x10}
	SIM_CMD_GET_RESPONSE = []byte{0xa0, 0xc0, 0x00, 0x00}
	SIM_CMD_READ_BIN     = []byte{0xa0, 0xb0, 0x00, 0x00}
	SIM_CMD_READ_RECORD  = []byte{0xa0, 0xb2, 0x00, 0x00}
	SIM_CMD_VERIFY_CHV1  = []byte{0xa0, 0x20, 0x00, 0x01, 0x08}

	/* USIM commands */
	USIM_CLA              = 0x00
	USIM_CMD_RUN_UMTS_ALG = []byte{0x00, 0x88, 0x00, 0x81, 0x22}
	USIM_CMD_GET_RESPONSE = []byte{0x00, 0xc0, 0x00, 0x00}

	SIM_RECORD_MODE_ABSOLUTE = 0x04

	USIM_FSP_TEMPL_TAG = 0x62

	USIM_TLV_FILE_DESC           = 0x82
	USIM_TLV_FILE_ID             = 0x83
	USIM_TLV_DF_NAME             = 0x84
	USIM_TLV_PROPR_INFO          = 0xA5
	USIM_TLV_LIFE_CYCLE_STATUS   = 0x8A
	USIM_TLV_FILE_SIZE           = 0x80
	USIM_TLV_TOTAL_FILE_SIZE     = 0x81
	USIM_TLV_PIN_STATUS_TEMPLATE = 0xC6
	USIM_TLV_SHORT_FILE_ID       = 0x88
	USIM_TLV_SECURITY_ATTR_8B    = 0x8B
	USIM_TLV_SECURITY_ATTR_8C    = 0x8C
	USIM_TLV_SECURITY_ATTR_AB    = 0xAB

	USIM_PS_DO_TAG = []byte{0x90}

	/* GSM files
	 * File type in first octet:
	 * 3F = Master File
	 * 7F = Dedicated File
	 * 2F = Elementary File under the Master File
	 * 6F = Elementary File under a Dedicated File
	 */
	SCARD_FILE_MF                 = 0x3F00
	SCARD_FILE_TELECOMM_DF        = 0x7f10
	SCARD_FILE_GSM_DF             = 0x7F20
	SCARD_FILE_UMTS_DF            = 0x7F50
	SCARD_FILE_GSM_EF_IMSI        = 0x6F07
	SCARD_FILE_USIM_SERVICE_TABLE = 0x6F38
	SCARD_FILE_USIM_EF_MSISDN     = 0x6F40
	SCARD_FILE_GSM_EF_MSISDN      = 0x6F40
	SCARD_FILE_GSM_EF_AD          = 0x6FAD
	SCARD_FILE_EF_DIR             = 0x2F00
	SCARD_FILE_EF_ICCID           = 0x2FE2
	SCARD_FILE_EF_CK              = 0x6FE1
	SCARD_FILE_EF_IK              = 0x6FE2

	SCARD_CHV1_OFFSET = []byte{13}
	SCARD_CHV1_FLAG   = []byte{0x80}

	//
	AKA_RAND_LEN = 16
	AKA_AUTN_LEN = 16
	AKA_AUTS_LEN = 14
	RES_MAX_LEN  = 16
	MAC_LEN      = 8
	IK_LEN       = 16
	CK_LEN       = 16
	AK_LEN       = 6
	SQN_LEN      = 6
	KEY_LEN      = 32

	//
	UNSYNC = errors.New("UMTS Synchronization-Failure")
)

type efdir struct {
	appl_template_tag uint /* 0x61 */
	appl_template_len uint
	appl_id_tag       uint /* 0x4f */
	aid_len           uint
	rid               [5]byte
	appl_code         [2]byte /* 0x1002 for 3G USIM */
	rest              []byte
}

func (e *efdir) parse(data []byte) {
	e.appl_template_tag = uint(data[0])
	e.appl_template_len = uint(data[1])
	e.appl_id_tag = uint(data[2])
	e.aid_len = uint(data[3])
	copy(e.rid[:], data[4:9])
	copy(e.appl_code[:], data[9:11])
	e.rest = data[11:]
}
