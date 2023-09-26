package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type DM3u8 struct {
	BaseUrl    string
	TsList     []string
	Key        string
	Key_URI    string
	Key_Method string
	Iv         string
	Cache_Path string
}

var (
	URL      string
	PATH     string
	LOG_PATH string
	ChI      chan string
)

func RequestClient(u string) []byte {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			req.Header.Del("Referer")
			// fmt.Println(req.Header)
			return nil
		},
	}
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 11; M2012K11AC) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36")
	resp, _ := client.Do(req)
	body_bit, _ := ioutil.ReadAll(resp.Body)
	return body_bit
}

func main_so() {}
func getOsArgsValue(s string, key string) string {
	// 查找=的下标
	index := strings.Index(s, "=")
	if index == -1 {
		return ""
	}
	if key != s[:index] {
		return ""
	}
	return s[index+1:]
}

func logPrintln(s string) {
	t_now := time.Now().String()[:19]
	t_now = "[" + strings.ReplaceAll(t_now, " ", "_") + "] -- "
	lstr := t_now + s + "\n"
	fmt.Print(lstr)
	f, _ := os.OpenFile(LOG_PATH, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	defer f.Close()
	f.WriteString(lstr)
}

// 检查全局变量
func Check() {
	ChI = make(chan string, 4)
	LOG_PATH = "./down.log"
	if URL == "" {
		logPrintln("URL为空!")
		os.Exit(1)
	}
	if !(strings.HasPrefix(URL, "http://") || strings.HasPrefix(URL, "https://")) {
		logPrintln("URL不是以http或者https开头!!")
		os.Exit(100)
	}
	if strings.Index(PATH, "/") == -1 {
		logPrintln("PATH路径中没有\"/\"")
		os.Exit(200)
	} else {
		lindex := strings.LastIndex(PATH, "/")
		err := os.MkdirAll(PATH[:lindex], os.ModePerm)
		if err != nil {
			logPrintln("创建文件夹出错-->" + PATH[:lindex])
			os.Exit(200)
		}
	}
}

func AES128Decrypt(crypted, key, iv []byte) ([]byte, error) {
	//	fmt.Println(crypted)
	//	fmt.Println(key)
	//	fmt.Println(iv)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	if len(iv) == 0 {
		iv = key
	}
	blockMode := cipher.NewCBCDecrypter(block, iv[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	length := len(origData)
	unPadding := int(origData[length-1])
	origData = origData[:(length - unPadding)]
	return origData, nil
}

func parseLineParameters(line string) map[string]string {
	linePattern := regexp.MustCompile(`([a-zA-Z-]+)=("[^"]+"|[^",]+)`)
	r := linePattern.FindAllStringSubmatch(line, -1)
	params := make(map[string]string)
	for _, arr := range r {
		params[arr[1]] = strings.Trim(arr[2], "\"")
	}
	return params
}

func completionUrl(url string, path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	if strings.HasPrefix(path, "/") {
		return url + path[1:]
	} else {
		return url + path
	}
}

func NewDMeu8(m3u string) *DM3u8 {
	dm3u := &DM3u8{}
	t := time.Now().UnixNano()
	dm3u.Cache_Path = "./cache/" + strconv.FormatInt(t, 10)
	os.MkdirAll(dm3u.Cache_Path, os.ModePerm)
	dm3u.BaseUrl = URL[:strings.LastIndex(URL, "/")+1]
	m3u_list := strings.Split(m3u, "\n")
	// fmt.Println(m3u_list)
	for i := 0; i < len(m3u_list); i++ {
		line := strings.TrimSpace(m3u_list[i])
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if strings.HasPrefix(line, "#EXT-X-KEY") {
				params := parseLineParameters(line)
				dm3u.Key_Method = params["METHOD"]
				dm3u.Key_URI = completionUrl(dm3u.BaseUrl, params["URI"])
				dm3u.Key = string(RequestClient(dm3u.Key_URI))

				dm3u.Iv = params["IV"]
			}
		} else {
			dm3u.TsList = append(dm3u.TsList, line)
		}
	}
	// fmt.Println(dm3u)

	return dm3u
}

func (dm *DM3u8) downTs(u string) {
	path := dm.Cache_Path + "/" + u[strings.LastIndex(u, "/")+1:]
	body_bit := RequestClient(u)

	if dm.Key_Method != "" {
		b, err := AES128Decrypt(body_bit, []byte(dm.Key), []byte(dm.Iv))
		if err != nil {
			logPrintln("解密失败!")
		}
		body_bit = b
	}
	// Some TS files do not start with SyncByte 0x47,
	// 一些 ts 文件不以同步字节 0x47 开头，
	//	they can not be played after merging,
	// 合并后不能播放，
	// Need to remove the bytes before the SyncByte 0x47(71).
	// 需要删除同步字节 0x47(71) 之前的字节。
	syncByte := uint8(71) // 0x47
	bLen := len(body_bit)
	for j := 0; j < bLen; j++ {
		if body_bit[j] == syncByte {
			//			fmt.Println(bytes[:j])
			body_bit = body_bit[j:]
			break
		}
	}
	file, _ := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
	defer file.Close()
	file.Write(body_bit)
	a := <-ChI
	// fmt.Println(path)
	fmt.Println(a)
}

func downM3u8(m3u string) {
	dm3 := NewDMeu8(m3u)
	for i := 0; i < len(dm3.TsList); i++ {
		go dm3.downTs(dm3.TsList[i])
		ChI <- dm3.TsList[i]
	}
}

func downFile(u string, p string) {
	resb := RequestClient(u)
	if string(resb[:7]) == "#EXTM3U" {
		downM3u8(string(resb))
	} else {
		ioutil.WriteFile(p, resb, 0666)
	}
}

func main() {
	for i := 1; i < len(os.Args); i++ {
		u := getOsArgsValue(os.Args[i], "-u")
		p := getOsArgsValue(os.Args[i], "-p")
		if u != "" {
			URL = u
		}
		if p != "" {
			PATH = p
		}

	}

	//==========================================
	Check()
	downFile(URL, PATH)
}
