package usim_go

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/free5gc/milenage"
	smartcard "github.com/sf1/go-card/smartcard"
	"github.com/sirupsen/logrus"
)

// algo     = "milenage";
// imei     = "356092040793011";
// imsi     = "208930000000001";
// k        = "8BAF473F2F8FD09487CCCBD7097C6862";
// using_op = true;
// op       = "11111111111111111111111111111111";

type Algo uint8

const (
	Milenage Algo = iota
	Xor
)

func (a Algo) String() string {
	return []string{"milenage", "xor"}[a]
}

type USIM struct {
	soft     bool
	algo     Algo
	imei     uint64
	imsi     uint64
	msisdn   string
	k        [16]byte
	op       [16]byte
	using_op bool
	opc      [16]byte
	amf      [2]byte
	mnc      uint16
	mncStr   string
	mcc      uint16
	mccStr   string
	// rest
	ak         []byte
	ik         []byte
	ck         []byte
	res        []byte
	auts       []byte
	ak_xor_sqn []byte
	//
	ctx      *smartcard.Context
	reader   *smartcard.Reader
	cardType int
	aid      []byte
}

func InitSoftUSIM(algo Algo, imei string, imsi string, k string, op string, opc string, soft bool) (u USIM, err error) {
	u.soft = soft
	u.algo = algo
	u.cardType = SCARD_USIM
	if u.imei, err = convert_imei(imei); err != nil {
		err = errors.New("failed convert imei")
		return
	}
	if u.imsi, err = convert_imsi(imsi); err != nil {
		err = errors.New("failed convert imsi")
		return
	}
	if u.k, err = convert_k(k); err != nil {
		err = errors.New("failed convert k")
		return
	}
	if len(op) == 32 {
		if u.op, err = convert_op(op); err != nil {
			err = errors.New("failed convert op")
			return
		}
	}
	if len(opc) == 32 {
		if u.opc, err = convert_op(opc); err != nil {
			err = errors.New("failed convert opc")
			return
		}
	}
	if u.mccStr, u.mncStr, err = extract_mcc_mnc(imsi); err != nil {
		err = errors.New("failed to extract mcc and mnc")
		return u, err
	} else {
		if u.mcc, u.mnc, err = convert_mcc_mnc(u.mccStr, u.mncStr); err != nil {
			return u, err
		}
	}
	if u.using_op {
		u.compute_opc()
	}
	return u, nil
}

func InitPcscUSIM(seq int) (u USIM, err error) {
	u.soft = false
	u.cardType = SCARD_USIM
	u.ctx, err = smartcard.EstablishContext()
	if err != nil {
		logrus.Fatalln("[EstablishContext]", err)
	}
	//
	readers, err := u.ctx.ListReadersWithCard()
	if err != nil {
		logrus.Error(err)
		return
	}
	logrus.Infof("Found %d readers", len(readers))
	for k, v := range readers {
		logrus.Infof("Reader %d: %s", k, v.Name())
	}
	if len(readers) == 0 {
		logrus.Error("please insert smart card")
		err = errors.New("please insert smart card")
		return
	} else if len(readers) == 1 {
		u.reader = readers[0]
	} else if seq == -1 {
		logrus.Error("multiple readers found, please select one")
		return
	} else if seq >= len(readers) {
		logrus.Errorf("found %d readers, but you choose %d\n", len(readers), seq)
		return
	} else {
		// to do: handle multiple readers choices
		logrus.Errorf("multiple readers found, using the %d\n", seq)
		u.reader = readers[seq]
		// return
	}
	//
	card, err := u.reader.Connect()
	if err != nil {
		logrus.Fatalln("[Card Connect]", err)
		return
	}
	defer card.Disconnect()
	// IMSI
	var imsi string
	if imsi, err = getIMSI(card); err != nil {
		logrus.Error(err)
		return
	}
	if u.imsi, err = convert_imsi(imsi); err != nil {
		logrus.Error(err)
		return
	}
	logrus.Debug("IMSI: ", imsi)
	//
	var msisdn string
	if msisdn, err = getMSISDN(card); err != nil {
		logrus.Error(err)
		// return
	}
	u.msisdn = msisdn
	// mcc mnc
	if u.mccStr, u.mncStr, err = extract_mcc_mnc(imsi); err != nil {
		err = errors.New("failed to extract mcc and mnc")
		return u, err
	} else {
		if u.mcc, u.mnc, err = convert_mcc_mnc(u.mccStr, u.mncStr); err != nil {
			return u, err
		}
	}
	if u.aid, err = selectAid(card); err != nil {
		logrus.Error(err)
	}
	return u, nil
}

func (u *USIM) GenAuthResMilenage(rand, autn [16]byte) (rest, ik, ck, auts []byte, err error) {
	if u.soft {
		if err = u.gen_auth_res_milenage(rand, autn); err != nil {
			logrus.Error(err)
			return
		}
	} else {
		var card *smartcard.Card
		if card, err = u.reader.Connect(); err != nil {
			logrus.Error(err)
			return
		}
		defer card.Disconnect()
		if u.res, u.ik, u.ck, u.auts, err = AKAVerify(card, u.cardType, u.aid, rand[:], autn[:]); err == UNSYNC {
			logrus.Info(err)
			auts = u.auts
			return
		} else if err != nil {
			logrus.Error(err)
			return
		}
	}

	rest = u.res
	ik = u.ik
	ck = u.ck
	auts = u.auts
	return
}

func (u *USIM) GenGSMAlg(rand []byte) (xres, kc []byte, err error) {
	if u.soft {
		logrus.Println(u.opc, u.k, rand)
		milenage.Gsm_milenage(u.opc[:], u.k[:], rand, xres, kc)
	} else {
		var card *smartcard.Card
		if card, err = u.reader.Connect(); err != nil {
			logrus.Error(err)
			return
		}
		defer card.Disconnect()
		if xres, kc, err = GSMAlg(card, SCARD_GSM_SIM, rand); err != nil {
			logrus.Error(err)
			return
		}
	}
	return
}

// extract_rand_autn unmarshal nonce and extract rand, autn
func ExtractRandAutn(nonce string) (rand, autn [16]byte) {
	sDec, _ := base64.StdEncoding.DecodeString(nonce)
	copy(rand[:], sDec[:16])
	copy(autn[:], sDec[16:])
	return rand, autn
}
func (u *USIM) Close() {
	if u.ctx != nil {
		u.ctx.Release()
	}
}

func (u USIM) IMSI() string {
	return fmt.Sprintf("%d", u.imsi)
}

func (u *USIM) ForceIMSI(imsi string) (err error) {
	u.imsi, err = convert_imsi(imsi)
	return
}

func (u USIM) MSISDN() string {
	return u.msisdn
}
