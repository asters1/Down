package main

import (
	"C"
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
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
	tsLen      int
}

var (
	URL      string
	PATH     string
	LOG_PATH string
	ChI      chan string
	wg       sync.WaitGroup
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
	CleanCache()
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
	dm3u.tsLen = len(dm3u.TsList)
	// fmt.Println(dm3u)

	return dm3u
}

func (dm *DM3u8) downTs(u string, i int) {
	// r := time.Duration(rand.Intn(3)) * time.Second
	// time.Sleep(r)
	// path := dm.Cache_Path + "/" + u[strings.LastIndex(u, "/")+1:]
	path := dm.Cache_Path + "/" + strconv.Itoa(i) + ".ts"
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
	// a := <-ChI
	wg.Done()
	<-ChI
	// fmt.Println(path)
	// fmt.Println(a)
}

func (dm *DM3u8) merge() {
	// 下载的段数应该等于m3u8段数
	missingCount := 0
	for idx := 0; idx < dm.tsLen; idx++ {
		tsFilename := strconv.Itoa(idx) + ".ts"
		f := filepath.Join(dm.Cache_Path, tsFilename)
		fmt.Println(f)
		if _, err := os.Stat(f); err != nil {
			// fmt.Println("缺失文件!!!")
			logPrintln("缺失文件!!")
			missingCount++
		}
	}
	if missingCount > 0 {
		logPrintln("缺失Ts文件，未下载完整!")
	}
	// 创建一个TS文件用于合并，所有的Segment文件都会写入到这个文件中。
	mFilePath := PATH
	mFile, err := os.Create(mFilePath)
	if err != nil {
		logPrintln("创建文件[" + mFilePath + "]失败!")
		os.Exit(500)
	}
	defer mFile.Close()
	writer := bufio.NewWriter(mFile)
	mergedCount := 0
	for segIndex := 0; segIndex < dm.tsLen; segIndex++ {
		tsFilename := strconv.Itoa(segIndex) + ".ts"
		bytes, err := ioutil.ReadFile(filepath.Join(dm.Cache_Path, tsFilename))
		_, err = writer.Write(bytes)
		if err != nil {
			continue
		}
		mergedCount++
		// tool.DrawProgressBar("merge",
		// 	float32(mergedCount)/float32(d.segLen), progressWidth)
	}
	_ = writer.Flush()
	// Remove `ts` folder

	if mergedCount != dm.tsLen {
		logPrintln("合成失败!!")
	} else {
		fmt.Println("合成成功!")
	}

	fmt.Printf("\n[output] %s\n", mFilePath)
}

func downM3u8(m3u string) {
	dm3 := NewDMeu8(m3u)
	for i := 0; i < len(dm3.TsList); i++ {
		wg.Add(1)
		go dm3.downTs(dm3.TsList[i], i)
		fmt.Println(i, dm3.TsList[i])
		ChI <- dm3.TsList[i]
	}
	wg.Wait()

	dm3.merge()
}

func downFile(u string, p string) {
	resb := RequestClient(u)
	if string(resb[:7]) == "#EXTM3U" {
		downM3u8(string(resb))
	} else {
		ioutil.WriteFile(p, resb, 0666)
	}
}

func CleanCache() {
	os.RemoveAll("./cache/")
}

// func C.CString(string) *C.char              //go字符串转化为char*
// func C.CBytes([]byte) unsafe.Pointer        // go 切片转化为指针
// func C.GoString(*C.char) string             //C字符串 转化为 go字符串
// func C.GoStringN(*C.char, C.int) string
// func C.GoBytes(unsafe.Pointer, C.int) []byte

// C 语言类型                 CGO 类型      Go语言类型
// char                       C.char        byte
// singed char                C.schar       int8
// unsigned char              C.uchar       uint8
// short                      C.short       int16
// unsigned short             C.ushort      uint16
// int                        C.int         int32
// unsigned int               C.uint        uint32
// unsigned long	            C.ulong	     uint32
// long long int	            C.longlong	   int64
// unsigned long long int     C.ulonglong   uint64
// float                      C.float       float32
// double                     C.double      float64
// size_t                     C.size_t      uint

//export GoDown
func GoDown(url *C.char, path *C.char) {
	URL = C.GoString(url)
	PATH = C.GoString(path)
	Check()
	downFile(URL, PATH)
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
