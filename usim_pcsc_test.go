package usim_go

import (
	"encoding/hex"
	"testing"

	"github.com/sf1/go-card/smartcard"
	"github.com/sirupsen/logrus"
)

func init() {
	// logrus.SetLevel(logrus.DebugLevel)
}
func TestISIM_Authentication(t *testing.T) {
	u, err := InitPcscUSIM(1)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	rand, autn := ExtractRandAutn("xl8/PLAk3uUQzVTgsuqUftS1DwdtGgAArZxo1AtoR3w=")
	u.GenAuthResMilenage(rand, autn)
}

func TestReadIMSI(t *testing.T) {
	var resp string
	ctx, err := smartcard.EstablishContext()
	if err != nil {
		logrus.Fatalln("[EstablishContext]", err)
	}
	defer ctx.Release()
	//
	var reader *smartcard.Reader
	readers, err := ctx.ListReadersWithCard()
	if err != nil {
		t.Error(err)
	}
	if len(readers) == 0 {
		t.Error("please insert smart card")
		return
	} else {
		reader = readers[0]
	}
	//
	card, err := reader.Connect()
	if err != nil {
		logrus.Fatalln("[Card Connect]", err)
	}
	defer card.Disconnect()
	if resp, err = getIMSI(card); err != nil {
		t.Error(err)
	}
	logrus.Debug(resp)
}
func TestReadICCID(t *testing.T) {
	var resp string
	ctx, err := smartcard.EstablishContext()
	if err != nil {
		logrus.Fatalln("[EstablishContext]", err)
	}
	defer ctx.Release()
	//
	var reader *smartcard.Reader
	readers, err := ctx.ListReadersWithCard()
	if err != nil {
		t.Error(err)
	}
	if len(readers) == 0 {
		t.Error("please insert smart card")
		return
	} else {
		reader = readers[0]
	}
	//
	card, err := reader.Connect()
	if err != nil {
		logrus.Fatalln("[Card Connect]", err)
	}
	defer card.Disconnect()
	if resp, err = getICCID(card); err != nil {
		t.Error(err)
	}
	logrus.Debug(resp)
}

func TestReadMSISDN(t *testing.T) {
	var resp string
	ctx, err := smartcard.EstablishContext()
	if err != nil {
		logrus.Fatalln("[EstablishContext]", err)
	}
	defer ctx.Release()
	//
	var reader *smartcard.Reader
	readers, err := ctx.ListReadersWithCard()
	if err != nil {
		t.Error(err)
	}
	if len(readers) == 0 {
		t.Error("please insert smart card")
		return
	} else {
		reader = readers[0]
	}
	//
	card, err := reader.Connect()
	if err != nil {
		logrus.Fatalln("[Card Connect]", err)
	}
	defer card.Disconnect()
	if resp, err = getMSISDN(card); err != nil {
		t.Error(err)
	}
	logrus.Debug(resp)
}
func TestAKAVerify(t *testing.T) {
	var resp string
	ctx, err := smartcard.EstablishContext()
	if err != nil {
		logrus.Fatalln("[EstablishContext]", err)
	}
	defer ctx.Release()
	//
	var reader *smartcard.Reader
	readers, err := ctx.ListReadersWithCard()
	if err != nil {
		t.Error(err)
	}
	if len(readers) == 0 {
		t.Error("please insert smart card")
		return
	} else {
		reader = readers[0]
	}
	//
	card, err := reader.Connect()
	if err != nil {
		logrus.Fatalln("[Card Connect]", err)
	}
	defer card.Disconnect()
	aid := []byte{0xa0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02, 0xff, 0x44, 0xff, 0x12, 0x89, 0x00, 0x00, 0x01, 0x00}
	rand_enb, autn_enb := ExtractRandAutn("+RGnCUSjBznUFr/rh61YWdP3pq5SDwAANkhzzFOaH+s=")
	if res, ik, ck, auts, err := AKAVerify(card, SCARD_USIM, aid, rand_enb[:], autn_enb[:]); err != nil {
		t.Error(err)
	} else {
		logrus.Info(res, ik, ck, auts)
	}
	logrus.Debug(resp)
}

func TestParseAKA(t *testing.T) {
	rst := []byte{
		0xdb, 0x08, 0xdb, 0xe8, 0x47, 0x27, 0xfd, 0x01, 0xed, 0xd1, 0x10, 0x0c, 0xd4, 0x7a, 0x13, 0x06,
		0xab, 0xe7, 0x45, 0x40, 0x11, 0x5e, 0x00, 0x0f, 0x71, 0x6c, 0xad, 0x10, 0xc1, 0x85, 0x22, 0x4f,
		0x2e, 0x6b, 0xdb, 0x9c, 0x69, 0x42, 0x65, 0x43, 0x72, 0x04, 0x37, 0x5b, 0x08, 0xe4, 0x02, 0x63,
		0x1f, 0x55, 0xb5, 0x67, 0x2f, 0x90, 0x00,
	}
	parseAKA(rst)
}
func TestGSMAlg(t *testing.T) {
	var resp string
	ctx, err := smartcard.EstablishContext()
	if err != nil {
		logrus.Fatalln("[EstablishContext]", err)
	}
	defer ctx.Release()
	//
	var reader *smartcard.Reader
	readers, err := ctx.ListReadersWithCard()
	if err != nil {
		t.Error(err)
	}
	if len(readers) == 0 {
		t.Error("please insert smart card")
		return
	} else {
		reader = readers[0]
	}
	//
	card, err := reader.Connect()
	if err != nil {
		logrus.Fatalln("[Card Connect]", err)
	}
	defer card.Disconnect()
	rand_enb, _ := hex.DecodeString("150ff8d7d6be2bebb782c67f2126e152")
	if sres, kc, err := GSMAlg(card, SCARD_USIM, rand_enb[:]); err != nil {
		t.Error(err)
	} else {
		logrus.Debug("XRES: ", hex.EncodeToString(sres), "KC: ", hex.EncodeToString(kc))
	}
	logrus.Debug(resp)
}
