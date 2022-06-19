package usim_go

import (
	"encoding/hex"
	"errors"
	"fmt"

	smartcard "github.com/sf1/go-card/smartcard"
	"github.com/sirupsen/logrus"
)

var cardType = SCARD_USIM

func get_aid(ctx *smartcard.Card) ([]byte, error) {
	var resp []byte
	var err error
	resp, err = _select_file(ctx, SCARD_FILE_EF_DIR, SCARD_USIM, []byte{})
	logrus.Debug(hex.Dump(resp))

	if err != nil {
		logrus.Error("reading FILE_ER_DIR failed")
		return nil, errors.New("reading FILE_EF_DIR failed")
	}

	return resp, nil
}

func get_record_len(ctx *smartcard.Card, recnum, mode int) (int, error) {
	var resp []byte
	var err error
	var cmd = []byte{}
	cmd = append(cmd, SIM_CMD_READ_RECORD...)
	// USIM
	cmd[0] = byte(USIM_CLA)
	cmd[2] = byte(recnum)
	cmd[3] = byte(mode)
	logrus.Debug("Sending command:\n", hex.Dump(cmd))
	if resp, err = ctx.Transmit(cmd); err != nil {
		logrus.Error("reading record length failed")
		return 0, err
	}
	logrus.Debug("Got response:\n", hex.Dump(resp))
	if len(resp) < 2 || (resp[0] != 0x6c && resp[0] != 0x67) {
		logrus.Error("SCARD: unexpected response to file length determination")
		return 0, errors.New("SCARD: unexpected response to file length determination")
	}
	rlen := uint(resp[1])
	return int(rlen), nil
}

func get_record(ctx *smartcard.Card, recLen, recnum, mode int) ([]byte, error) {
	var resp []byte
	var err error
	var cmd = []byte{}
	cmd = append(cmd, SIM_CMD_READ_RECORD...)
	cmd[0] = byte(USIM_CLA)
	cmd[2] = byte(recnum)
	cmd[3] = byte(mode)
	cmd = append(cmd, byte(recLen))
	if resp, err = ctx.Transmit(cmd); err != nil {
		logrus.Error("reading record failed")
		return nil, err
	}
	if len(resp) != recLen+2 {
		logrus.Debugf("SCARD: record read returned unexpected length %d (expected %d)\n", len(resp), recLen+2)
		return nil, errors.New("unexpected return length")
	}

	if resp[recLen] != 0x90 || resp[recLen+1] != 0x00 {
		logrus.Debugf("SCARD: record read returned unexpected status %02x %02x (expected 90 00)\n", resp[recLen], resp[recLen+1])
		return nil, errors.New("unexpected status")
	}
	return resp, nil
}

func swapHex(hexs []byte) {
	for i, num := range hexs {
		num = ((num << 4) & 0xf0) | ((num >> 4) & 0x0f)
		hexs[i] = num
	}
}

func parse_fsp_templ(buf []byte, fileType int) (fileLen int, err error) {
	var pos = 0
	if int(buf[pos]) != USIM_FSP_TEMPL_TAG {
		errStr := "SCARD: file header did not start with FSP template tag"
		logrus.Error(errStr)
		err = errors.New(errStr)
		return
	}
	pos += 2
	for pos < len(buf)-2 {
		fType := int(buf[pos])
		fLen := int(buf[pos+1])
		pos += 2
		logrus.Debugf("SCARD: file header TLV 0x%02x len=%d\n", fType, fLen)
		switch fType {
		case fileType:
			if fLen == 1 {
				fileLen = int(buf[pos])
			} else {
				fileLen = int(buf[pos])<<8 + int(buf[pos+1])
			}
			return
		}
		pos += fLen
	}
	return
}
func read_file(ctx *smartcard.Card, fLen int, simType int) (resp []byte, err error) {
	var cmd = []byte{}
	cmd = append(cmd, SIM_CMD_READ_BIN...)
	cmd = append(cmd, byte(fLen))
	if simType == SCARD_USIM {
		cmd[0] = byte(USIM_CLA)
	}
	logrus.Debug("Sending command:\n", hex.Dump(cmd))
	if resp, err = ctx.Transmit(cmd); err != nil {
		return nil, errors.New("transmit select file cmd failed")
	}
	logrus.Debug("Got response:\n", hex.Dump(resp))
	if len(resp) != fLen+2 {
		errStr := fmt.Sprintf("SCARD: unexpected resp len %d (expected %d)", len(resp), fLen+2)
		return nil, errors.New(errStr)
	}
	if resp[fLen] != 0x90 || resp[fLen+1] != 0x00 {
		errStr := fmt.Sprintf("SCARD: file read returned unexpected status %02x %02x (expected 90 00)", resp[fLen], resp[fLen+1])
		return nil, errors.New(errStr)
	}
	err = nil
	return
}

func getIMSI(ctx *smartcard.Card) (string, error) {
	logrus.Debug("SCARD: reading IMSI from (GSM) EF-IMSI")
	var resp []byte
	var usimAppAid []byte
	var err error
	// check whether support USIM
	if _, err = _select_file(ctx, SCARD_FILE_MF, SCARD_USIM, nil); err != nil {
		logrus.Debug("USIM is not supported. Trying to use GSM SIM")
		cardType = SCARD_GSM_SIM
	} else {
		logrus.Debug("USIM is supported")
	}
	// select AID
	if usimAppAid, err = selectAid(ctx); err != nil {
		logrus.Error("Found USIM APP AID failed: ", err)
	}
	if _, err = _select_file(ctx, 0x0000, cardType, usimAppAid); err != nil {
		logrus.Error("Select USIM APP file failed: ", err)
	}
	// reading IMSI
	logrus.Debug("SCARD: reading IMSI from (GSM) EF-IMSI")
	if resp, err = _select_file(ctx, SCARD_FILE_GSM_EF_IMSI, cardType, nil); err != nil {
		logrus.Debug("reading SCARD_FILE_GSM_EF_IMSI failed: ", err)
		return "", errors.New("reading SCARD_FILE_GSM_EF_IMSI failed")
	}

	var fLen int
	if fLen, err = parse_fsp_templ(resp, USIM_TLV_FILE_SIZE); err != nil {
		errStr := "get USIM_TLV_FILE_SIZE failed"
		logrus.Debug(errStr, err)
		return "", errors.New("get USIM_TLV_FILE_SIZE failed")
	}
	imsilen := (fLen-2)*2 + 1
	logrus.Debugf("SCARD: IMSI file length=%d imsilen=%d", fLen, imsilen)
	if resp, err = read_file(ctx, fLen, SCARD_USIM); err != nil {
		errStr := fmt.Sprintf("reading SCARD_FILE_GSM_EF_IMSI failed: %d", err)
		logrus.Debug(errStr)
		return "", errors.New(errStr)
	}
	swapHex(resp[:fLen])
	return hex.EncodeToString(resp[:fLen])[3:], nil
}

func getICCID(ctx *smartcard.Card) (iccid string, err error) {
	var resp []byte
	var cmd = []int{
		SCARD_FILE_MF,
		SCARD_FILE_EF_ICCID,
	}
	for _, cmd_ := range cmd {
		if resp, err = _select_file(ctx, cmd_, SCARD_USIM, nil); err != nil {
			logrus.Debug("reading SCARD_FILE_EF_ICCID failed: ", err)
			return "", errors.New("reading SCARD_FILE_EF_ICCID failed")
		}
	}
	var fLen int
	if fLen, err = parse_fsp_templ(resp, USIM_TLV_FILE_SIZE); err != nil {
		errStr := "get SCARD_FILE_EF_ICCID failed"
		logrus.Debug(errStr, err)
		return "", errors.New("get SCARD_FILE_EF_ICCID failed")
	}
	logrus.Debugf("SCARD: file Lenth %d", fLen)
	if resp, err = read_file(ctx, fLen, SCARD_USIM); err != nil {
		errStr := fmt.Sprintf("reading SCARD_FILE_EF_ICCID failed: %d", err)
		logrus.Debug(errStr)
		return "", errors.New(errStr)
	}
	swapHex(resp[:fLen])
	iccid = hex.EncodeToString(resp[:fLen])
	return
}

func getMSISDN(ctx *smartcard.Card) (msisdn string, err error) {
	var resp []byte
	var cmd1 = []int{
		SCARD_FILE_MF,
		SCARD_FILE_TELECOMM_DF,
		SCARD_FILE_GSM_EF_MSISDN,
	}

	for _, cmd_ := range cmd1 {
		if _, err = _select_file(ctx, cmd_, SCARD_USIM, nil); err != nil {
			aid := []byte{0xa0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02, 0xff, 0x44, 0xff, 0x12, 0x89, 0x00, 0x00, 0x01, 0x00}
			_select_file(ctx, SCARD_FILE_MF, SCARD_USIM, nil)
			_select_file(ctx, 0, SCARD_USIM, aid)
			_select_file(ctx, SCARD_FILE_GSM_EF_MSISDN, SCARD_USIM, nil)
			return "", errors.New("reading MSISDN failed")

		}
	}
	var rLen int
	if rLen, err = get_record_len(ctx, 1, SIM_RECORD_MODE_ABSOLUTE); err != nil {
		logrus.Error(err)
		return
	}
	logrus.Debug("record length ", rLen)
	if resp, err = get_record(ctx, rLen, 1, SIM_RECORD_MODE_ABSOLUTE); err != nil {
		logrus.Error(err)
		return
	}
	resp = resp[16:]
	swapHex(resp[2:])
	dailLen := int((resp[0]-2)*2 + 1)
	if dailLen <= len(hex.EncodeToString(resp[2:])) {
		msisdn = hex.EncodeToString(resp[2:])[:dailLen]
	} else {
		err = errors.New("reading MSISDN failed")
	}
	return
}

func AKAVerify(ctx *smartcard.Card, simType int, aid []byte, rand, auth []byte) (res, ik, ck, auts []byte, err error) {
	var resp []byte
	var cmd []byte
	var getResp []byte
	cmd = USIM_CMD_RUN_UMTS_ALG
	cmd = append(cmd, byte(AKA_RAND_LEN))
	cmd = append(cmd, rand...)
	cmd = append(cmd, byte(AKA_AUTN_LEN))
	cmd = append(cmd, auth...)
	getResp = append(getResp, USIM_CMD_GET_RESPONSE...)

	if simType == SCARD_USIM {
		cmd[0] = byte(USIM_CLA)
	}
	_select_file(ctx, SCARD_FILE_MF, SCARD_USIM, nil)
	_select_file(ctx, 0, SCARD_USIM, aid)
	logrus.Debug("Sending command:\n", hex.Dump(cmd))
	if resp, err = ctx.Transmit(cmd); err != nil {
		errStr := "AKAVerify: sending command failed"
		logrus.Error(errStr)
		return
	}
	logrus.Debug("Got response:\n", hex.Dump(resp))
	if len(resp) == 2 && resp[0] == 0x98 && resp[1] == 0x62 {
		// Authentication error, application specific
		err = errors.New("SCARD: UMTS auth failed - MAC != XMAC")
		return
	}
	if len(resp) != 2 || resp[0] != 0x61 {
		errStr := fmt.Sprintf("SCARD: unexpected response for UMTS auth request (len=%d resp=0x%02X%02X)", len(resp), resp[0], resp[1])
		err = errors.New(errStr)
		return
	}
	getResp = append(getResp, resp[1])
	if resp, err = ctx.Transmit(getResp); err != nil {
		errStr := "reading response failed"
		logrus.Error(errStr, err)
		err = errors.New(errStr)
		return
	}
	// logrus.Infof("SCARD: UMTS get response result\n%s\n", hex.Dump(resp))
	if len(resp) >= 2+AKA_AUTS_LEN && resp[0] == 0xdc && int(resp[1]) == AKA_AUTS_LEN {
		logrus.Debug("SCARD: UMTS Synchronization-Failure")
		auts = resp[2 : 2+AKA_AUTS_LEN]
		err = UNSYNC
		return
	}
	if len(resp) >= 6+IK_LEN+CK_LEN && resp[0] == 0xdb {
		res, ck, ik, err = parseAKA(resp)
	}
	return
}

func parseAKA(buf []byte) (res, ck, ik []byte, err error) {
	// fmt.Println(hex.Dump(buf))
	/* RES */
	var resLen = int(buf[1])
	var resStart = 2
	if resLen > RES_MAX_LEN {
		errStr := "SCARD: Invalid RES"
		logrus.Error(errStr)
		err = errors.New("SCARD: Invalid RES")
		return
	}
	res = buf[resStart : resStart+resLen]
	// fmt.Println(hex.Dump(res))
	/* CK */
	var ckLen = int(buf[resStart+resLen])
	var ckStart = resStart + resLen + 1
	if ckLen != CK_LEN {
		errStr := "SCARD: Invalid CK"
		logrus.Error(errStr)
		err = errors.New(errStr)
		return
	}
	ck = buf[ckStart : ckStart+ckLen]
	// fmt.Println(hex.Dump(ck))
	/* IK */
	var ikLen = int(buf[ckStart+ckLen])
	// fmt.Printf("%02x\n",ikLen)
	var ikStart = ckStart + ckLen + 1
	if ikLen != IK_LEN {
		errStr := "SCARD: Invalid IK"
		logrus.Error(errStr)
		err = errors.New(errStr)
		return
	}
	ik = buf[ikStart : ikStart+ikLen]
	// fmt.Println(hex.EncodeToString( res), hex.EncodeToString(ck), hex.EncodeToString(ik))
	return
}
func selectAid(ctx *smartcard.Card) (aid []byte, err error) {
	var resp []byte
	var rlen int
	var efdir_ efdir
	_select_file(ctx, SCARD_FILE_MF, SCARD_USIM, []byte{})
	get_aid(ctx)
	for rec := 1; rec < 10; rec++ {
		if rlen, err = get_record_len(ctx, rec, SIM_RECORD_MODE_ABSOLUTE); err != nil {
			logrus.Error(ctx)
			continue
		}

		if resp, err = get_record(ctx, int(rlen), rec, SIM_RECORD_MODE_ABSOLUTE); err != nil {
			logrus.Error(err)
		}
		// fmt.Println(hex.Dump(resp))

		efdir_.parse(resp)
		if efdir_.appl_template_tag != 0x61 {
			logrus.Debugf("SCARD: Unexpected application template tag 0x%x\n", efdir_.appl_template_tag)
			continue
		}
		if efdir_.appl_template_len > uint(rlen-2) {
			logrus.Debugf("SCARD: Too long application template (len=%d rlen=%d)\n", efdir_.appl_template_len, rlen)
			continue
		}
		if efdir_.appl_id_tag != 0x4f {
			logrus.Debugf("SCARD: Unexpected application identifier tag 0x%x\n", efdir_.appl_id_tag)
			continue
		}

		var aid_len = efdir_.aid_len
		if aid_len < 1 || aid_len > 16 {
			logrus.Debugf("SCARD: Invalid AID length %d\n", aid_len)
			continue
		}

		if efdir_.appl_code[0] == 0x10 && efdir_.appl_code[1] == 0x02 {
			logrus.Debugf("SCARD: 3G USIM app found from EF_DIR record %d", rec)
			break
		}

	}
	aid = resp[4 : 4+efdir_.aid_len]
	return
}
