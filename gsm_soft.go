package usim_go

// func (u *USIM) gen_GSM_milenage(rand [16]byte) (err error) {
// 	if u.opc, err = GsmMilenageGenOpc(u.k, u.op); err != nil {
// 		return
// 	}

// 	return nil
// }

// func GsmMilenageGenOpc(ki, op [16]byte) (opc [16]byte, err error) {
// 	var opc_ []byte
// 	if opc_, err = AESEncrypt(ki[:], op[:]); err != nil {
// 		return
// 	}
// 	if opc_, err = LogicalXOR(opc_, op[:]); err != nil {
// 		return
// 	}
// 	copy(opc[:], opc_)
// 	return
// }

// func AESEncrypt(key, buf []byte) (res []byte, err error) {
// 	var b cipher.Block
// 	if b, err = aes.NewCipher(key); err != nil {
// 		return
// 	}
// 	b.Encrypt(res, buf)
// 	return
// }

// func LogicalXOR(str1, str2 []byte) (res []byte, err error) {
// 	if len(str1) != len(str2) {
// 		err = fmt.Errorf("length of bytes slices is not equivalent: %d!= %d", len(str1), len(str2))
// 		return
// 	}
// 	res = make([]byte, len(str1))
// 	for i := range str1 {
// 		res[i] = str1[i] ^ str2[i]
// 	}
// 	return
// }
