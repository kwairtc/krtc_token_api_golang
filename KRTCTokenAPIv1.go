package main

import (
	"bytes"
	"compress/zlib"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"time"
	"strings"
	"fmt"
)

/*
base url encode 实现
*/
func base64urlEncode(data []byte) string {
	str := base64.StdEncoding.EncodeToString(data)
	str = strings.Replace(str, "+", "*", -1)
	str = strings.Replace(str, "/", "-", -1)
	str = strings.Replace(str, "=", "_", -1)
	return str
}

/*
base url decode 实现
*/
func base64urlDecode(str string) ([]byte, error) {
	str = strings.Replace(str, "_", "=", -1)
	str = strings.Replace(str, "-", "/", -1)
	str = strings.Replace(str, "*", "+", -1)
	return base64.StdEncoding.DecodeString(str)
}

/*
*【功能说明】用于签发 KRTC 服务中必须要使用的 Token 鉴权票据
*
*【参数说明】
* appid  - SDK APPID 
* key    - SDK APPSign 密钥
* userid - 用户id，限制长度为32字节，只允许包含大小写英文字母（a-zA-Z）、数字（0-9）及下划线和连词符。
* expire - Token 票据的过期时间，单位是秒，比如 86400 代表生成的 Token 票据在一天后就无法再使用了。
*/
func genUserToken(appid int, key string, userid string, expire int) (string, error) {
	return genToken(appid, key, userid, expire, nil)
}

func hmacsha256(appid int, key string, identifier string, currTime int64, expire int, base64UserBuf *string) string {
	var contentToBeSigned string
	contentToBeSigned = "TLS.identifier:" + identifier + "\n"
	contentToBeSigned += "TLS.sdkappid:" + strconv.Itoa(appid) + "\n"
	contentToBeSigned += "TLS.time:" + strconv.FormatInt(currTime, 10) + "\n"
	contentToBeSigned += "TLS.expire:" + strconv.Itoa(expire) + "\n"
	if nil != base64UserBuf {
		contentToBeSigned += "TLS.userbuf:" + *base64UserBuf + "\n"
	}

	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(contentToBeSigned))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func genToken(appid int, key string, identifier string, expire int, userbuf []byte) (string, error) {
	currTime := time.Now().Unix()
	tokenDoc := make(map[string]interface{})
	tokenDoc["TLS.ver"] = "1.0"
	tokenDoc["TLS.identifier"] = identifier
	tokenDoc["TLS.sdkappid"] = appid
	tokenDoc["TLS.expire"] = expire
	tokenDoc["TLS.time"] = currTime
	var base64UserBuf string
	if nil != userbuf {
		base64UserBuf = base64.StdEncoding.EncodeToString(userbuf)
		tokenDoc["TLS.userbuf"] = base64UserBuf
		tokenDoc["TLS.token"] = hmacsha256(appid, key, identifier, currTime, expire, &base64UserBuf)
	} else {
		tokenDoc["TLS.token"] = hmacsha256(appid, key, identifier, currTime, expire, nil)
	}

	data, err := json.Marshal(tokenDoc)
	if err != nil {
		return "", err
	}

	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	if _, err = w.Write(data); err != nil {
		return "", err
	}
	if err = w.Close(); err != nil {
		return "", err
	}

	return base64urlEncode(b.Bytes()), nil
}

const (
	appid = 9726578939
	key = "a173af0fa8c1008bc269e0064f32c2e408292279"
)

func main()  {
	token, err := genUserToken(appid, key, "12345678", 86400*180)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println(token)
	}
}
