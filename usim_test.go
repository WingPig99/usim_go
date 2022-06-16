package usim_go

import (
	"bytes"
	"testing"
)

func TestConvertMCCMNC(t *testing.T) {
	mcc, mnc, err := convert_mcc_mnc("001", "466")
	if err != nil {
		t.Error(err)
	}
	if mcc != 0xF001 {
		t.Error("convert mcc failed")
	}
	if mnc != 0xF466 {
		t.Error("convert mnc failed")
	}
}

func TestConvert_k(t *testing.T) {
	k, err := convert_k("8BAF473F2F8FD09487CCCBD7097C6862")
	if err != nil {
		t.Log(err)
	}
	if !bytes.Equal(k[:], []byte{0x8B, 0xAF, 0x47, 0x3F, 0x2F, 0x8F, 0xD0, 0x94, 0x87, 0xCC, 0xCB, 0xD7, 0x09, 0x7C, 0x68, 0x62}) {
		t.Error("convert k failed")
	}
}

func TestConvert_op(t *testing.T) {
	k, err := convert_op("11111111111111111111111111111111")
	if err != nil {
		t.Log(err)
	}
	if !bytes.Equal(k[:], []byte{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}) {
		t.Error("convert k failed")
	}
}

func TestConvert_imsi(t *testing.T) {
	imsi, err := convert_imsi("208930000000001")
	if err != nil {
		t.Log((err))
	}
	if imsi != 208930000000001 {
		t.Error("convert imsi failed", imsi)
	}
}

/*
Debug output generated from the OpenAirInterface HSS:

Converted 02f839 to plmn 208.93
Query: SELECT `key`,`sqn`,`rand`,`OPc` FROM `users` WHERE `users`.`imsi`='208930000000001'
Key: 8b.af.47.3f.2f.8f.d0.94.87.cc.cb.d7.09.7c.68.62.
Received SQN 00000000000000006999 converted to 6999
SQN: 00.00.00.00.1b.57.
RAND: 7c.f6.e2.6b.20.0a.ca.27.a1.a0.91.40.f5.cf.9d.62.
OPc: 8e.27.b6.af.0e.69.2e.75.0f.32.66.7a.3b.14.60.5d.
Generated random
RijndaelKeySchedule: K 8BAF473F2F8FD09487CCCBD7097C6862
MAC_A   : 84.ba.37.b0.f6.73.4d.d1.
SQN     : 00.00.00.00.1b.57.
RAND    : 88.38.c3.55.c8.78.aa.57.21.49.fe.69.db.68.6b.5a.
RijndaelKeySchedule: K 8BAF473F2F8FD09487CCCBD7097C6862
AK      : d7.44.51.9b.3e.fd.
CK      : 05.d3.53.3d.fe.7b.e7.2d.42.c7.bb.02.f2.8e.da.7f.
IK      : 26.33.a2.0b.dc.a8.9d.78.58.ba.42.47.8b.e4.d2.4d.
XRES    : e5.5d.88.27.91.8d.ac.c6.
AUTN    : d7.44.51.9b.25.aa.80.00.84.ba.37.b0.f6.73.4d.d1.
0x05 0xd3 0x53 0x3d 0xfe 0x7b 0xe7 0x2d 0x42 0xc7 0xbb 0x02 0xf2 0x8e
0xda 0x7f 0x26 0x33 0xa2 0x0b 0xdc 0xa8 0x9d 0x78 0x58 0xba 0x42 0x47
0x8b 0xe4 0xd2 0x4d 0x10 0x02 0xf8 0x39 0x00 0x03 0xd7 0x44 0x51 0x9b
0x25 0xaa 0x00 0x06
KASME   : a8.27.57.5e.ea.1a.10.17.3a.a1.bf.ce.4b.0c.21.85.e0.51.ef.bd.91.7f.fe.f5.1f.74.29.61.f9.03.7a.35.
*/
func Test_gen_auth_res_milenage(t *testing.T) {
	u, err := InitSoftUSIM(Milenage, "356092040793011", "208930000000001", "8BAF473F2F8FD09487CCCBD7097C6862", "11111111111111111111111111111111", "",true)
	u.compute_opc()
	if err != nil {
		t.Error(err)
	}
	rand_enb := [16]byte{0x88, 0x38, 0xc3, 0x55, 0xc8, 0x78, 0xaa, 0x57, 0x21, 0x49, 0xfe, 0x69, 0xdb, 0x68, 0x6b, 0x5a}
	autn_enb := [16]byte{0xd7, 0x44, 0x51, 0x9b, 0x25, 0xaa, 0x80, 0x00, 0x84, 0xba, 0x37, 0xb0, 0xf6, 0x73, 0x4d, 0xd1}
	u.gen_auth_res_milenage(rand_enb, autn_enb)
	ak := []byte{0xd7, 0x44, 0x51, 0x9b, 0x3e, 0xfd}
	if !bytes.Equal(u.ak[:], ak) {
		t.Errorf("AK failed. expect %X, got %X\n", ak, u.ak)
	}
	ck := []byte{0x05, 0xd3, 0x53, 0x3d, 0xfe, 0x7b, 0xe7, 0x2d, 0x42, 0xc7, 0xbb, 0x02, 0xf2, 0x8e, 0xda, 0x7f}
	if !bytes.Equal(u.ck[:], ck) {
		t.Errorf("CK failed. expect %X, got %X\n", ck, u.ck)
	}
	ik := []byte{0x26, 0x33, 0xa2, 0x0b, 0xdc, 0xa8, 0x9d, 0x78, 0x58, 0xba, 0x42, 0x47, 0x8b, 0xe4, 0xd2, 0x4d}
	if !bytes.Equal(u.ik[:], ik) {
		t.Errorf("CK failed. expect %X, got %X\n", ik, u.ik)
	}
}
