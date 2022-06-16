package usim_go

import (
	"encoding/hex"
	"errors"

	smartcard "github.com/sf1/go-card/smartcard"
	"github.com/sirupsen/logrus"
)

func GSMAlg(ctx *smartcard.Card, simType int, rand []byte) (sres, kc []byte, err error) {
	var resp []byte
	var cmd []byte
	var getResp []byte
	cmd = SIM_CMD_RUN_GSM_ALG
	// cmd = append(cmd, byte(16))
	cmd = append(cmd, rand...)
	getResp = append(getResp, SIM_CMD_GET_RESPONSE...)

	// choose GSM_DF
	_select_file(ctx, SCARD_FILE_GSM_DF, SCARD_GSM_SIM, nil)

	logrus.Debug("Sending command:\n", hex.Dump(cmd))
	if resp, err = ctx.Transmit(cmd); err != nil {
		errStr := "GSMAlg: sending command failed"
		logrus.Error(errStr)
		return
	}
	logrus.Debug("Got response:\n", hex.Dump(resp))
	if resp[0] != 0x9F {
		errStr := "GSMAlg: run alg failed"
		logrus.Error(errStr)
		return
	}
	getResp = append(getResp, resp[1])
	logrus.Debug("Sending command:\n", hex.Dump(getResp))
	if resp, err = ctx.Transmit(getResp); err != nil {
		errStr := "reading response failed"
		logrus.Error(errStr, err)
		err = errors.New(errStr)
		return
	}
	logrus.Debug("Got response: \n", hex.Dump(resp))
	sres = resp[0:4]
	kc = resp[4:12]
	return
}
