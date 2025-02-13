package main

import (
	"crypto/cipher"
	"encoding/hex"
	"reflect"
	"testing"
)

func Test_pkcs7Unpad(t *testing.T) {
	blockSize := 16
	byteLength := 100
	// 创建一个空的字节切片
	var byteSlice []byte
	// 动态添加 100 个字节
	for i := 0; i < byteLength; i++ {
		byteSlice = append(byteSlice, byte(i))
	}
	//填充长度
	paddingLength := blockSize - byteLength%blockSize
	var wantByteSlice []byte
	// 构建want集
	for _, b := range byteSlice {
		wantByteSlice = append(wantByteSlice, b)
	}
	for i := 0; i < paddingLength; i++ {
		wantByteSlice = append(wantByteSlice, byte(paddingLength))
	}
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "100个字节去填充",
			args: args{
				data: wantByteSlice,
			},
			want:    byteSlice,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pkcs7Unpad(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("pkcs7Unpad() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("pkcs7Unpad() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_pkcs7Pad(t *testing.T) {
	blockSize := 16
	byteLength := 100
	// 创建一个空的字节切片
	var byteSlice []byte
	// 动态添加 100 个字节
	for i := 0; i < byteLength; i++ {
		byteSlice = append(byteSlice, byte(i))
	}
	//填充长度
	paddingLength := blockSize - byteLength%blockSize
	var wantByteSlice []byte
	// 构建want集
	for _, b := range byteSlice {
		wantByteSlice = append(wantByteSlice, b)
	}
	for i := 0; i < paddingLength; i++ {
		wantByteSlice = append(wantByteSlice, byte(paddingLength))
	}
	type args struct {
		data      []byte
		blockSize int
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "填充100个字节",
			args: args{
				data:      byteSlice,
				blockSize: blockSize,
			},
			want: wantByteSlice,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pkcs7Pad(tt.args.data, tt.args.blockSize); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("pkcs7Pad() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_decryptFile(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	method, err := getMethod("aes", key)
	if err != nil {
		return
	}
	byteLength := 100
	var byteSlice []byte
	// 动态添加 100 个字节
	for i := 0; i < byteLength; i++ {
		byteSlice = append(byteSlice, byte(i))
	}
	encryptRet := encryptFile(method, byteSlice)
	type args struct {
		block cipher.Block
		dst   []byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		// TODO: Add test cases.
		{
			name: "aes加密解密测试",
			args: args{
				block: method,
				dst:   encryptRet,
			},
			want: byteSlice,
		},
		{
			name: "des加密解密测试",
			args: args{
				block: method,
				dst:   encryptRet,
			},
			want: byteSlice,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := decryptFile(tt.args.block, tt.args.dst); !reflect.DeepEqual(got, tt.want) || err != nil {
				t.Errorf("decryptFile() = %v, want %v", got, tt.want)
			}

		})
	}
}
