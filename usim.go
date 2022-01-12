package usim_go

// #cgo LDFLAGS: -lmbedtls -lmbedx509 -lmbedcrypto -lmbedtls -lmbedx509 -lmbedcrypto
// #include "usim.hpp"
import "C"
import (
	"encoding/hex"
	"errors"
	"log"
	"strings"
	"unsafe"
)

// algo     = "milenage";
// imei     = "356092040793011";
// imsi     = "208930000000001";
// k        = "8BAF473F2F8FD09487CCCBD7097C6862";
// using_op = true;
// op       = "11111111111111111111111111111111";

// convert_k
func convert_k(k string) (k_ [16]byte, err error) {
	if len(k) != 32 {
		err = errors.New("convert k failed")
		return
	}
	if k__, err := hex.DecodeString(k); err != nil {
		return k_, err
	} else {
		copy(k_[:], k__)
	}

	return
}

// convert_imsi
func convert_imsi(imsi string) (imsi_ uint64, err error) {
	if len(imsi) != 15 {
		err = errors.New("the length of imsi is wrong")
	}
	imsi_ = 0
	for _, v := range imsi {
		imsi_ *= 10
		imsi_ += uint64(v) - '0'
	}
	return
}

// convert_imsi
func convert_imei(imei string) (imei_ uint64, err error) {
	if len(imei) != 15 {
		err = errors.New("the length of imei is wrong")
	}
	imei_ = 0
	for _, v := range imei {
		imei_ *= 10
		imei_ += uint64(v) - '0'
	}
	return
}

// convert_op
func convert_op(op string) (op_ [16]byte, err error) {
	if len(op) != 32 {
		err = errors.New("convert k failed")
		return
	}
	if op__, err := hex.DecodeString(op); err != nil {
		return op_, err
	} else {
		copy(op_[:], op__)
	}

	return
}

func extract_mcc_mnc(imsi string) (mcc, mnc string, err error) {
	if len(imsi) != 15 {
		err = errors.New("extract mcc/mnc failed")
		return
	}
	mccLen := 3
	mncLen := 2
	// US MCC uses 3 MNC digits
	if strings.Compare(imsi[:3], "310") == 0 || strings.Compare(imsi[:3], "311") == 0 || strings.Compare(imsi[:3], "312") == 0 || strings.Compare(imsi[:3], "313") == 0 || strings.Compare(imsi[:3], "310") == 0 || strings.Compare(imsi[:3], "316") == 0 {
		mncLen = 3
	}
	return imsi[:mccLen], imsi[mccLen : mccLen+mncLen], nil
}

// convert_mcc_mnc
func convert_mcc_mnc(mcc, mnc string) (mcc_ uint16, mnc_ uint16, err error) {
	// C.mcc =
	// convert MCC from string to BCD-code
	mcc_ = 0xF000
	if len(mcc) == 3 {
		mcc_ |= ((uint16)(mcc[0]-'0') << 8)
		mcc_ |= ((uint16)(mcc[1]-'0') << 4)
		mcc_ |= ((uint16)(mcc[2] - '0'))
	} else {
		err = errors.New("convert ncc failed")
		return
	}

	// convert MNC to BCD-code
	if len(mnc) == 3 {
		mnc_ = 0xF000
		mnc_ |= ((uint16)(mnc[0]-'0') << 8)
		mnc_ |= ((uint16)(mnc[1]-'0') << 4)
		mnc_ |= ((uint16)(mnc[2] - '0'))
	} else if len(mnc) == 2 {
		mnc_ = 0xFF00
		mnc_ |= ((uint16)(mnc[0]-'0') << 4)
		mnc_ |= ((uint16)(mnc[1] - '0'))
	} else {
		err = errors.New("convert mnc failed")
		return
	}
	return mcc_, mnc_, nil
}

type Algo uint8

const (
	Milenage Algo = iota
	Xor
)

func (a Algo) String() string {
	return []string{"milenage", "xor"}[a]
}

type USIM struct {
	algo     Algo
	imei     uint64
	imsi     uint64
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
	ak   [6]byte
	ik   [16]byte
	ck   [16]byte
	auts [14]byte
}

func InitUSIM(algo Algo, imei string, imsi string, k string, op string, opc string) (u USIM, err error) {
	u.algo = algo
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

func (u *USIM) compute_opc() {
	C.compute_opc((*C.uchar)(&u.k[0]), (*C.uchar)(&u.op[0]), (*C.uchar)(&u.opc[0]))
}
func (u USIM) pass_k_to_c() {
	C.set_k((*C.uchar)(&u.k[0]))
}

func (u USIM) pass_op_to_c() {
	C.set_op((*C.uchar)(&u.op[0]))
}
func (u USIM) pass_opc_to_c() {
	C.set_opc((*C.uchar)(&u.opc[0]))
}
func (u USIM) pass_amf_to_c() {
	C.set_amf((*C.uchar)(&u.amf[0]))
}

func (u *USIM) fetch_rest() {
	ak_ := C.GoBytes(unsafe.Pointer(&C.ak), 6)
	copy(u.ak[:], ak_)
	ik_ := C.GoBytes(unsafe.Pointer(&C.ik), 16)
	copy(u.ik[:], ik_)
	ck_ := C.GoBytes(unsafe.Pointer(&C.ck), 16)
	copy(u.ck[:], ck_)
	auts_ := C.GoBytes(unsafe.Pointer(&C.auts), 14)
	copy(u.auts[:], auts_)
}
func (u USIM) gen_auth_res_xor(rand, autn [16]byte) {
	C.auth_algo = C.auth_algo_xor
	u.pass_k_to_c()
	u.pass_op_to_c()
	u.pass_amf_to_c()
	res := [16]byte{0x00}
	res_len := 16
	ak_xor_sqn := [6]byte{}
	tmp := C.int(res_len)
	a := C.gen_auth_res_xor((*C.uchar)(&rand[0]), (*C.uchar)(&autn[0]), (*C.uchar)(&res[0]), (*C.int)(&tmp), (*C.uchar)(&ak_xor_sqn[0]))
	if a != 0 {
		log.Println("call C.gen_auth_res_xor failed")
	} else {
		u.fetch_rest()
	}

}

func (u USIM) gen_auth_res_milenage(rand, autn [16]byte) {
	C.auth_algo = C.auth_algo_xor
	u.pass_k_to_c()
	u.pass_opc_to_c()
	u.pass_amf_to_c()
	res := [16]byte{0x00}
	res_len := 16
	ak_xor_sqn := [6]byte{}
	tmp := C.int(res_len)
	a := C.gen_auth_res_milenage((*C.uchar)(&rand[0]), (*C.uchar)(&autn[0]), (*C.uchar)(&res[0]), (*C.int)(&tmp), (*C.uchar)(&ak_xor_sqn[0]))
	if a != 0 {
		log.Println("call C.gen_auth_res_milenage failed")
	} else {
		u.fetch_rest()
	}
}
