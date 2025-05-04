package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type DeviceInfo struct {
	Version             int    `json:"version"`
	FlashSize           int    `json:"flash_size"`
	PsramSize           int    `json:"psram_size"`
	MinimumFreeHeapSize int    `json:"minimum_free_heap_size"`
	MacAddress          string `json:"mac_address"`
	UUID                string `json:"uuid"`
	ChipModelName       string `json:"chip_model_name"`
	ChipInfo            struct {
		Model    int `json:"model"`
		Cores    int `json:"cores"`
		Revision int `json:"revision"`
		Features int `json:"features"`
	} `json:"chip_info"`
	Application struct {
		Name        string `json:"name"`
		Version     string `json:"version"`
		CompileTime string `json:"compile_time"`
		IDFVersion  string `json:"idf_version"`
	} `json:"application"`
	PartitionTable []struct {
		Label   string `json:"label"`
		Type    int    `json:"type"`
		Subtype int    `json:"subtype"`
		Address int    `json:"address"`
		Size    int    `json:"size"`
	} `json:"partition_table"`
	OTA struct {
		Label string `json:"label"`
	} `json:"ota"`
	Board struct {
		Type     string   `json:"type"`
		Name     string   `json:"name"`
		Features []string `json:"feature"`
		IP       string   `json:"ip"`
		MAC      string   `json:"mac"`
	} `json:"board"`
}

type MQTT struct {
	Endpoint       string `json:"endpoint"`
	ClientID       string `json:"client_id"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	PublishTopic   string `json:"publish_topic"`
	SubscribeTopic string `json:"subscribe_topic"`
}

type ServerResponse struct {
	MQTT      MQTT `json:"mqtt"`
	WebSocket struct {
		URL   string `json:"url"`
		Token string `json:"token"`
	} `json:"websocket"`
	ServerTime struct {
		Timestamp      int64 `json:"timestamp"`
		TimezoneOffset int   `json:"timezone_offset"`
	} `json:"server_time"`
	Firmware struct {
		Version string `json:"version"`
		URL     string `json:"url"`
	} `json:"firmware"`
	Activation struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		Challenge string `json:"challenge"`
	} `json:"activation"`
}

type ActivationPayload struct {
	Algorithm    string `json:"algorithm"`
	SerialNumber string `json:"serial_number"`
	Challenge    string `json:"challenge"`
	HMAC         string `json:"hmac"`
}

type ActivationRequest struct {
	Payload ActivationPayload `json:"Payload"`
}

func GetDeviceConfig(deviceInfo *DeviceInfo, deviceID, clientID string) (*ServerResponse, error) {
	url := "https://api.tenclass.net/xiaozhi/ota/"

	jsonData, err := json.Marshal(deviceInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal device info: %v", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Device-Id", deviceID)
	req.Header.Set("Client-Id", clientID)
	req.Header.Set("Activation-Version", "1")
	req.Header.Set("User-Agent", "lc-esp32-s3/xiaozhi-1.6.0")

	//打印header
	fmt.Println("header: ", req.Header)
	fmt.Println("url: ", url)
	fmt.Println("jsonData: ", string(jsonData))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	fmt.Println("ota resp: ", string(body))

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var serverResp ServerResponse
	if err := json.Unmarshal(body, &serverResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return &serverResp, nil
}

func CreateDefaultDeviceInfo(uuid string, mac string, boardName string) *DeviceInfo {
	deviceInfo := &DeviceInfo{
		Version:             2,
		FlashSize:           16777216,
		PsramSize:           8388608,
		MinimumFreeHeapSize: 7265024,
		MacAddress:          mac,
		UUID:                uuid,
		ChipModelName:       "esp32s3",
	}
	deviceInfo.ChipInfo.Model = 9
	deviceInfo.ChipInfo.Cores = 2
	deviceInfo.ChipInfo.Revision = 0
	deviceInfo.ChipInfo.Features = 20
	deviceInfo.Application.Name = "xiaozhi"
	deviceInfo.Application.Version = "1.6.0"
	deviceInfo.Application.CompileTime = "2025-4-16T12:00:00Z"
	deviceInfo.Application.IDFVersion = "v5.3.2"
	deviceInfo.OTA.Label = "app0"
	deviceInfo.Board.Type = "lc-esp32-s3"
	deviceInfo.Board.Name = "立创ESP32-S3开发板"
	deviceInfo.Board.Features = []string{"wifi", "ble", "psram", "octal_flash"}
	deviceInfo.Board.IP = "10.0.0.171"
	deviceInfo.Board.MAC = mac

	// Add partition table
	deviceInfo.PartitionTable = []struct {
		Label   string `json:"label"`
		Type    int    `json:"type"`
		Subtype int    `json:"subtype"`
		Address int    `json:"address"`
		Size    int    `json:"size"`
	}{
		{Label: "nvs", Type: 1, Subtype: 2, Address: 36864, Size: 24576},
		{Label: "otadata", Type: 1, Subtype: 0, Address: 61440, Size: 8192},
		{Label: "app0", Type: 0, Subtype: 0, Address: 65536, Size: 1966080},
		{Label: "app1", Type: 0, Subtype: 0, Address: 2031616, Size: 1966080},
		{Label: "spiffs", Type: 1, Subtype: 130, Address: 3997696, Size: 1966080},
	}

	return deviceInfo
}

func activateDevice(deviceID, clientID, serialNumber, hmacKey, challenge string) (*ServerResponse, error) {
	url := "https://api.tenclass.net/xiaozhi/ota/activate"

	// 创建 HMAC
	h := hmac.New(sha256.New, []byte(hmacKey))
	h.Write([]byte(challenge))
	hmacValue := hex.EncodeToString(h.Sum(nil))

	// 构建请求数据
	payload := ActivationPayload{
		Algorithm:    "hmac-sha256",
		SerialNumber: serialNumber,
		Challenge:    challenge,
		HMAC:         hmacValue,
	}

	request := ActivationRequest{
		Payload: payload,
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal activation request: %v", err)
	}

	fmt.Println("激活请求数据: ", string(jsonData))

	//循环10次
	for i := 0; i < 10; i++ {
		req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %v", err)
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Device-Id", deviceID)
		req.Header.Set("Client-Id", clientID)

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to send request: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %v", err)
		}

		if resp.StatusCode == http.StatusOK {
			fmt.Printf("激活成功, resp: %+v\n", string(body))
			//验证成功
			return nil, nil
		}

		if resp.StatusCode == 202 {
			fmt.Println("等待验证码, 等待10秒后重试")
			time.Sleep(10 * time.Second)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
		}

		var serverResp ServerResponse
		if err := json.Unmarshal(body, &serverResp); err != nil {
			return nil, fmt.Errorf("failed to unmarshal response: %v", err)
		}
	}

	return nil, nil
}
