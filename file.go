package usim_go

import (
	"encoding/hex"
	"errors"
	"fmt"

	smartcard "github.com/sf1/go-card/smartcard"
	"github.com/sirupsen/logrus"
)

func _select_file(ctx *smartcard.Card, fileId int, simType int, aid []byte) ([]byte, error) {
	var resp []byte
	var err error
	var cmd = []byte{}
	var getResp []byte
	cmd = append(cmd, SIM_CMD_SELECT...)
	getResp = append(getResp, SIM_CMD_GET_RESPONSE...)
	if simType == SCARD_USIM {
		cmd[0] = byte(USIM_CLA)
		cmd[3] = 0x04
		getResp[0] = byte(USIM_CLA)
	}
	logrus.Debugf("SCARD: select file 0x%04X", fileId)

	if len(aid) > 0 {
		logrus.Debug("SCARD: select file by AID")
		cmd[2] = 0x04 //select by aid
		cmd[4] = byte(len(aid))
		cmd = append(cmd, aid...)
	} else {
		cmd = append(cmd, []byte{0x00, 0x00}...)
		cmd[5] = byte(fileId >> 8)
		cmd[6] = byte(fileId & 0xff)
	}
	logrus.Debug("Sending command:\n", hex.Dump(cmd))
	if resp, err = ctx.Transmit(cmd); err != nil {
		logrus.Error(err)
		return nil, errors.New("transmit select file cmd failed")
	}
	logrus.Debug("Got response:\n", hex.Dump(resp))
	if len(resp) != 2 {
		return nil, fmt.Errorf("SCARD: unexpected resp len %d (expected 2)", len(resp))
	}
	if resp[0] == 0x98 && resp[1] == 0x04 {
		return nil, errors.New("SCARD: Security status not satisfied")
	}
	if resp[0] == 0x6e {
		return nil, errors.New("SCARD: used CLA not supported")
	}
	if resp[0] != 0x6c && resp[0] != 0x9f && resp[0] != 0x61 {
		return nil, fmt.Errorf("SCARD: unexpected response 0x%02x (expected 0x61, 0x6c, or 0x9f)", resp[0])
	}

	/* Normal ending of command; resp[1] bytes available */
	getResp = append(getResp, resp[1])
	logrus.Debugf("SCARD: trying to get response (%d bytes)\n", resp[1])
	logrus.Debug("Sending command:\n", hex.Dump(getResp))
	if resp, err = ctx.Transmit(getResp); err != nil {
		return nil, errors.New("transmit get response cmd failed")
	}
	logrus.Debug("Got response:\n", hex.Dump(resp))
	// fmt.Println(hex.Dump(resp))
	return resp, nil
}
