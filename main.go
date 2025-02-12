package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

func main() {
	// 创建一个默认的Gin路由引擎
	r := gin.Default()
	r.LoadHTMLGlob("templates/*")
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	// 设置文件上传的HTML页面
	r.GET("/upload", func(c *gin.Context) {
		c.HTML(http.StatusOK, "upload.html", nil)
	})

	// 处理文件上传
	r.POST("/upload", func(c *gin.Context) {
		// 从表单中获取文件
		file, err := c.FormFile("file")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Failed to get file from form",
			})
			return
		}
		open, err := file.Open()
		defer open.Close()
		all, err := io.ReadAll(open)
		options := c.PostForm("options")
		method, err := getMethod(options, key)
		if err != nil {
			return
		}
		pad := encryptFile(method, all)

		err = os.WriteFile("encrypt.txt", pad, 0644)
		if err != nil {
			fmt.Println("Error encrypting file:", err)
			return
		}

		// 设置文件保存路径
		filePath := filepath.Join("uploads", file.Filename)

		// 保存文件到指定路径
		if err := c.SaveUploadedFile(file, filePath); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to save file",
			})
			return
		}

		// 返回成功响应
		c.JSON(http.StatusOK, gin.H{
			"message":  "File uploaded successfully",
			"filename": file.Filename,
			"size":     file.Size,
			"path":     filePath,
		})
	})

	// 处理文件下载
	r.GET("/download", func(c *gin.Context) {
		encryptFilePath := "encrypt.txt" // 文件路径
		decryptFilePath := "decrypt.txt"
		file, err := os.ReadFile(encryptFilePath)
		if err != nil {
			fmt.Println("Error read encrypt file:", err)
		}
		m := c.Query("method")

		method, err := getMethod(m, key)
		unpad := decryptFile(method, file)
		err = os.WriteFile("decrypt.txt", unpad, 0644)
		if err != nil {
			fmt.Println("Error decrypt file:", err)
		}
		c.File(decryptFilePath)
	})

	// 启动Gin服务
	if err := r.Run(":8080"); err != nil {
		log.Fatal("Failed to start server:", err)
	}

	fmt.Println("File encrypted successfully.")
}

func getMethod(method string, key []byte) (cipher.Block, error) {
	switch method {
	case "aes":
		return aes.NewCipher(key)
	case "des":
		return des.NewCipher(key)
	default:
		return nil, errors.New("no support")
	}
}

// 加密文件
func encryptFile(block cipher.Block, dst []byte) []byte {
	pad := pkcs7Pad(dst, block.BlockSize())
	block.Encrypt(pad, pad)
	return pad
}

// 解密文件
func decryptFile(block cipher.Block, dst []byte) []byte {
	block.Decrypt(dst, dst)

	unpad, err := pkcs7Unpad(dst)
	if err != nil {
		fmt.Println("file upack fail")
	}
	// 将加密后的数据写入文件
	return unpad
}

// PKCS#7 填充
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// PKCS#7 去除填充
func pkcs7Unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("input data is empty")
	}
	padding := int(data[length-1])
	if padding > length || padding == 0 {
		return nil, fmt.Errorf("invalid padding size")
	}
	// 检查填充字节是否正确
	for i := len(data) - padding; i < len(data); i++ {
		if int(data[i]) != padding {
			return nil, errors.New("填充字节不正确")
		}
	}
	return data[:length-padding], nil
}
