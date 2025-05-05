package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"net"
	"time"
)

type UDPClient struct {
	udpConn    *net.UDPConn
	serverAddr *net.UDPAddr
	aesKey     string
	aesNonce   string
	localSeq   uint32
}

func NewUDPClient(serverAddr string, port int, aesKey, aesNonce string) (*UDPClient, error) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", serverAddr, port))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve UDP address: %v", err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP connection: %v", err)
	}

	return &UDPClient{
		udpConn:    conn,
		serverAddr: addr,
		aesKey:     aesKey,
		aesNonce:   aesNonce,
		localSeq:   0,
	}, nil
}

func (c *UDPClient) Close() {
	if c.udpConn != nil {
		c.udpConn.Close()
	}
}

func AesCTREncrypt(key, nonce, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	stream := cipher.NewCTR(block, nonce)
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

func AesCTRDecrypt(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	stream := cipher.NewCTR(block, nonce)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}

func (c *UDPClient) aesCTREncrypt(key, nonce, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	stream := cipher.NewCTR(block, nonce)
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

func (c *UDPClient) aesCTRDecrypt(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	stream := cipher.NewCTR(block, nonce)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}

func (c *UDPClient) decryptAudioData(key []byte, data []byte) ([]byte, error) {
	//分离nonce和密文
	nonce := data[:16]
	ciphertext := data[16:]

	//解密
	decryptedData, err := c.aesCTRDecrypt(key, nonce, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %v", err)
	}

	return decryptedData, nil
}

func (c *UDPClient) SendAudioData(audioData []byte) error {
	// 生成新的nonce
	c.localSeq = (c.localSeq + 1) & 0xFFFFFFFF

	// 构建nonce字符串: 固定前缀 + 长度 + 原始nonce + 序列号
	nonceHex := c.aesNonce[:4] + // 固定前缀 (01000000)
		fmt.Sprintf("%04x", len(audioData)) + // 数据长度，4个十六进制字符
		c.aesNonce[8:24] + // 原始nonce
		fmt.Sprintf("%08x", c.localSeq) // 序列号，8个十六进制字符

	//fmt.Printf("c.aesNonce: %s len: %d, nonceHex: %s len: %d\n", c.aesNonce, len(c.aesNonce), nonceHex, len(nonceHex))

	// 加密数据
	key, err := hex.DecodeString(c.aesKey)
	if err != nil {
		return fmt.Errorf("failed to decode AES key: %v", err)
	}

	nonceBytes, err := hex.DecodeString(nonceHex)
	if err != nil {
		return fmt.Errorf("failed to decode nonce: %v", err)
	}

	// 检查IV长度
	//fmt.Printf("IV长度: %d 字节, 内容: %x\n", len(nonceBytes), nonceBytes)

	iv := nonceBytes

	encryptedData, err := c.aesCTREncrypt(key, iv, audioData)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %v", err)
	}

	// 拼接nonce和密文
	packet := append(nonceBytes, encryptedData...)

	// 发送数据包
	_, err = c.udpConn.Write(packet)
	if err != nil {
		return fmt.Errorf("failed to send UDP packet: %v", err)
	}

	//fmt.Printf("发送数据: nonce=%s, seq=%d, dataLen=%d\n", nonceHex, c.localSeq, len(audioData))

	return nil
}

func (c *UDPClient) ReceiveAudioData(key []byte, cb func(key []byte, data []byte)) error {
	go func() {
		for {
			buffer := make([]byte, 1024)
			n, _, err := c.udpConn.ReadFromUDP(buffer)
			if err != nil {
				fmt.Println(err)
				return
			}

			if !firstAudio {
				firstAudio = true
				fmt.Printf("收到第一条音频消息, 耗时: %d ms\n", time.Now().UnixMilli()-sendAudioEndTs)
			}

			cb(key, buffer[:n])
		}
	}()

	return nil
}
