package spiders

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/html"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"

	"asdan.qiniu.com/logger"
)

func GetFakeIp() string {
	part1 := rand.Intn(159) + 12
	part2 := rand.Intn(255) + 1
	part3 := rand.Intn(255) + 1
	part4 := rand.Intn(255) + 1
	return fmt.Sprintf("%d.%d.%d.%d", part1, part2, part3, part4)
}

// SpiderHeader return http client header
func SpiderHeader(referer string) (header http.Header) {
	header = http.Header{}
	header.Set("Accept-Language", "zh-CN,zh;q=0.8,en-US;q=0.6,en;q=0.4,zh-TW;q=0.2")
	header.Set("Upgrade-Insecure-Requests", "1")
	header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36")
	header.Set("Accept", "*/*")
	header.Set("Referer", referer)
	header.Set("Connection", "keep-alive")
	header.Set("Cache-Control", "max-age=0")
	header.Set("X-Forwarded-For", GetFakeIp())
	return
}

func GetDocumentFromBody(resp *http.Response, charset string) (doc *goquery.Document, err error) {
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, ErrElementNotFound
	}

	switch charset {
	case "gbk":
		reader := transform.NewReader(resp.Body, simplifiedchinese.GBK.NewDecoder())
		doc, err = goquery.NewDocumentFromReader(reader)
	default:
		doc, err = goquery.NewDocumentFromResponse(resp)
	}

	return
}

func SpiderClientWithProxy(u string, ip string, port int) (doc *goquery.Document, err error) {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}

	req.Header = SpiderHeader(u)

	client := http.Client{}
	proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%d", ip, port))
	if err != nil {
		return
	}
	client = http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy:                 http.ProxyURL(proxyURL),
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	doc, err = GetDocumentFromBody(resp, "")

	return
}

type SpiderClientConfig struct {
	Charset          string
	NoFollowRedirect bool
	Referer          string
}

func SpiderClientWithConfig(url string, config SpiderClientConfig) (doc *goquery.Document, err error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	refer := url
	if config.Referer != "" {
		refer = config.Referer
	}
	req.Header = SpiderHeader(refer)

	client := http.Client{}

	if config.NoFollowRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	doc, err = GetDocumentFromBody(resp, config.Charset)

	return
}

// SpiderClient 通过 URL 获取网页内容，并反馈 qoquery.Document
// 处理Non-UTF8 html页面
// https://github.com/PuerkitoBio/goquery/wiki/Tips-and-tricks#handle-non-utf8-html-pages
// http://mengqi.info/html/2015/201507071345-using-golang-to-convert-text-between-gbk-and-utf-8.html
func SpiderClient(url string, charsets ...string) (doc *goquery.Document, err error) {
	var charset string
	if len(charsets) > 0 {
		charset = charsets[0]
	}
	return SpiderClientWithConfig(url, SpiderClientConfig{
		Charset: charset,
	})
}

// UniqueSlice 删除 slice 中重复的，或空值
func UniqueSlice(slice *[]string) {
	found := make(map[string]bool)
	total := 0
	for i, val := range *slice {
		if len(val) == 0 {
			continue
		}
		if _, ok := found[val]; !ok {
			found[val] = true
			(*slice)[total] = (*slice)[i]
			total++
		}

	}
	*slice = (*slice)[:total]
}

// --------------------------------------------------------------------

// DefaultTransport 默认 HTTP Transport
var DefaultTransport = NewTransportTimeout(time.Duration(5)*time.Second, 0)

// NewTransportTimeout 返回指定超时时间的 Transport 对象
func NewTransportTimeout(dial, resp time.Duration) http.RoundTripper {
	t := &http.Transport{ // DefaultTransport
		Proxy:               http.ProxyFromEnvironment,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	t.Dial = (&net.Dialer{
		Timeout:   dial,
		KeepAlive: 30 * time.Second,
	}).Dial
	t.ResponseHeaderTimeout = resp
	return t
}

// SpiderRPC a golang http client
type SpiderRPC struct {
	*http.Client
	Header  http.Header
	Cookies []*http.Cookie
}

// DefaultSpiderRPCClient a golang default http client
var DefaultSpiderRPCClient = SpiderRPC{
	Client: &http.Client{Transport: DefaultTransport},
}

// NewSpiderRPCTimeout return a golang http client
func NewSpiderRPCTimeout(dial, resp time.Duration) SpiderRPC {
	return SpiderRPC{
		Client: &http.Client{Transport: NewTransportTimeout(dial, resp)},
	}
}

// --------------------------------------------------------------------

// Get send get method request
func (r SpiderRPC) Get(l *logger.Logger, url string) (resp *http.Response, err error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	return r.Do(l, req)
}

// GetDocument send get method request
func (r SpiderRPC) GetDocument(l *logger.Logger, url string) (doc *goquery.Document, err error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}

	resp, err := r.Do(l, req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	return goquery.NewDocumentFromResponse(resp)
}

// PostEx send post method request with url
func (r SpiderRPC) PostEx(l *logger.Logger, url string) (resp *http.Response, err error) {
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return
	}
	return r.Do(l, req)
}

// PostWith send post method request with url, bodyType, body and bodyLength(64)
func (r SpiderRPC) PostWith(l *logger.Logger, url1 string, bodyType string, body io.Reader, bodyLength int64) (resp *http.Response, err error) {
	req, err := http.NewRequest("POST", url1, body)
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", bodyType)
	req.ContentLength = bodyLength
	return r.Do(l, req)
}

// PostWithForm send post method request with url and form data
func (r SpiderRPC) PostWithForm(l *logger.Logger, url1 string, data map[string][]string) (resp *http.Response, err error) {
	msg := url.Values(data).Encode()
	return r.PostWith(l, url1, "application/x-www-form-urlencoded", strings.NewReader(msg), int64(len(msg)))
}

// PostWithJSON send post method request with url and application/json data
func (r SpiderRPC) PostWithJSON(l *logger.Logger, url1 string, data interface{}) (resp *http.Response, err error) {
	msg, err := json.Marshal(data)
	if err != nil {
		return
	}
	return r.PostWith(l, url1, "application/json", bytes.NewReader(msg), int64(len(msg)))
}

// --------------------------------------------------------------------

// Do 发送 HTTP Request, 并返回 HTTP Response
func (r SpiderRPC) Do(l *logger.Logger, req *http.Request) (resp *http.Response, err error) {
	// debug
	start := time.Now()
	defer func() {
		if err != nil {

		} else {
			method := req.Method
			methodColor := colorForMethod(method)
			statusCode := resp.StatusCode
			statusColor := colorForStatus(statusCode)

			fmt.Printf("[%s] \033[33m[%v]\033[0m\t[SpiderRPC] |%s %3d %s| %13v |%s %s %s|\t%s\n",
				l.ReqID(),
				start.Format("2006-01-02 15:04:05.999999"),
				statusColor, statusCode, reset,
				time.Now().Sub(start),
				methodColor, method, reset,
				req.URL.String(),
			)
		}
	}()

	for rName, rHeader := range r.Header {
		if req.Header.Get(rName) == "" {
			req.Header[rName] = rHeader
		}
	}

	if len(r.Cookies) > 0 {
		req.Header.Del("Cookie")
		for _, cookie := range r.Cookies {
			req.AddCookie(cookie)
		}
	}

	return r.Client.Do(req)
}

// --------------------------------------------------------------------

// RespError interface
type RespError interface {
	ErrorDetail() string
	Error() string
	HttpCode() int
}

// ErrorInfo type
type ErrorInfo struct {
	Err     string   `json:"error"`
	Reqid   string   `json:"reqid"`
	Details []string `json:"details"`
	Code    int      `json:"code"`
}

// ErrorDetail return error detail
func (r *ErrorInfo) ErrorDetail() string {
	msg, _ := json.Marshal(r)
	return string(msg)
}

// Error return error message
func (r *ErrorInfo) Error() string {
	if r.Err != "" {
		return r.Err
	}
	return http.StatusText(r.Code)
}

// HTTPCode return rpc http StatusCode
func (r *ErrorInfo) HTTPCode() int {
	return r.Code
}

// --------------------------------------------------------------------

type errorRet struct {
	Error string `json:"error"`
}

// ResponseError return response error
func ResponseError(resp *http.Response) (err error) {
	e := &ErrorInfo{
		Details: resp.Header["X-Log"],
		Reqid:   resp.Header.Get("X-Reqid"),
		Code:    resp.StatusCode,
	}
	if resp.StatusCode > 299 {
		if resp.ContentLength != 0 {
			if ct := resp.Header.Get("Content-Type"); strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]) == "application/json" {
				var ret1 errorRet
				json.NewDecoder(resp.Body).Decode(&ret1)
				e.Err = ret1.Error
			}
		}
	}
	return e
}

// CallRet parse http response
func CallRet(l *logger.Logger, ret interface{}, resp *http.Response) (err error) {
	return callRet(l, ret, resp)
}

// callRet parse http response
func callRet(l *logger.Logger, ret interface{}, resp *http.Response) (err error) {
	defer func() {
		io.Copy(ioutil.Discard, resp.Body)
		resp.Body.Close()
	}()

	if resp.StatusCode/100 == 2 || resp.StatusCode/100 == 3 {
		if ret != nil && resp.ContentLength != 0 {
			err = json.NewDecoder(resp.Body).Decode(ret)
			if err != nil {
				return
			}
		}
		return nil
	}
	return ResponseError(resp)
}

// CallWithForm send post method request with url and form data then parse response
func (r SpiderRPC) CallWithForm(l *logger.Logger, ret interface{}, url1 string, param map[string][]string) (err error) {
	resp, err := r.PostWithForm(l, url1, param)
	if err != nil {
		return err
	}
	return callRet(l, ret, resp)
}

// CallWithJSON send post method request with url and application/json data then parse response
func (r SpiderRPC) CallWithJSON(l *logger.Logger, ret interface{}, url1 string, param interface{}) (err error) {
	resp, err := r.PostWithJSON(l, url1, param)
	if err != nil {
		return err
	}
	return callRet(l, ret, resp)
}

// CallWith send post method request with url, bodyType, body and bodyLength then parse response
func (r SpiderRPC) CallWith(l *logger.Logger, ret interface{}, url1 string, bodyType string, body io.Reader, bodyLength int64) (err error) {
	resp, err := r.PostWith(l, url1, bodyType, body, bodyLength)
	if err != nil {
		return err
	}
	return callRet(l, ret, resp)
}

// Call send post method request with url then parse response
func (r SpiderRPC) Call(l *logger.Logger, ret interface{}, url1 string) (err error) {
	resp, err := r.PostWith(l, url1, "application/x-www-form-urlencoded", nil, 0)
	if err != nil {
		return err
	}
	return callRet(l, ret, resp)
}

// GetCall send get method request with url then parse response
func (r SpiderRPC) GetCall(l *logger.Logger, ret interface{}, url1 string) (err error) {
	resp, err := r.Get(l, url1)
	if err != nil {
		return err
	}
	return callRet(l, ret, resp)
}

// GetCallWithForm send get method request with url and param then parse response
func (r SpiderRPC) GetCallWithForm(l *logger.Logger, ret interface{}, url1 string, param map[string][]string) (err error) {
	payload := url.Values(param).Encode()
	if strings.ContainsRune(url1, '?') {
		url1 += "&"
	} else {
		url1 += "?"
	}
	url1 += payload
	resp, err := r.Get(l, url1)
	if err != nil {
		return err
	}
	return callRet(l, ret, resp)
}

// --------------------------------------------------------------------

var (
	green   = string([]byte{27, 91, 57, 55, 59, 52, 50, 109})
	white   = string([]byte{27, 91, 57, 48, 59, 52, 55, 109})
	yellow  = string([]byte{27, 91, 57, 55, 59, 52, 51, 109})
	red     = string([]byte{27, 91, 57, 55, 59, 52, 49, 109})
	blue    = string([]byte{27, 91, 57, 55, 59, 52, 52, 109})
	magenta = string([]byte{27, 91, 57, 55, 59, 52, 53, 109})
	cyan    = string([]byte{27, 91, 57, 55, 59, 52, 54, 109})
	reset   = string([]byte{27, 91, 48, 109})
)

func colorForStatus(code int) string {
	switch {
	case code >= 200 && code < 300:
		return green
	case code >= 300 && code < 400:
		return white
	case code >= 400 && code < 500:
		return yellow
	default:
		return red
	}
}

func colorForMethod(method string) string {
	switch method {
	case "GET":
		return blue
	case "POST":
		return cyan
	case "PUT":
		return yellow
	case "DELETE":
		return red
	case "PATCH":
		return green
	case "HEAD":
		return magenta
	case "OPTIONS":
		return white
	default:
		return reset
	}
}

func StrTrim(before, pre, suf string) (after string) {
	after = strings.TrimSpace(before)
	after = strings.TrimPrefix(after, pre)
	after = strings.TrimSuffix(after, suf)
	after = strings.TrimSpace(after)
	return
}

func StrReplace(before, old, new string) string {
	return strings.Replace(strings.TrimFunc(before, unicode.IsSpace), old, new, -1)
}

func StrReplaceSpace(before string, old ...string) string {
	for _, o := range old {
		before = StrReplace(before, o, "")
	}
	return before
}

func GetParentTextOnly(s *goquery.Selection) (str string) {
	nodes := s.Contents().Nodes
	for _, node := range nodes {
		if node.Type == html.TextNode {
			data := strings.TrimSpace(node.Data)
			if data != "\n" {
				str = data
				return
			}
		}
	}
	return
}

func GetNowDate() (date string) {
	return time.Now().Format("2006-01-02")
}

func CreateCookieByName(name, value string) (cookie *http.Cookie) {
	cookie = &http.Cookie{}
	cookie.Name = name
	cookie.Value = value
	return
}

func GetInfoFromRegexp(str, re string) (res string) {
	reg := regexp.MustCompile(re)

	if matches := reg.FindStringSubmatch(str); len(matches) == 2 {
		res = matches[1]
	}

	return
}

func SpiderClientRetry(maxRetry int, url string) (doc *goquery.Document, errs []error) {
	var err error
	for i := 1; i <= maxRetry; i++ {
		doc, err = SpiderClient(url)
		if err != nil {
			errs = append(errs, err)
			if i == maxRetry {
				errs = append(errs, ErrRetryFailed)
				return nil, errs
			}
			errs = append(errs, errors.New(fmt.Sprintf("SpiderClient failed, url:%s, have retried:%d.", url, i)))
		} else {
			break
		}
		time.Sleep(time.Second * 2)
	}
	return doc, errs
}

func getSpiderErr(errs []error) (err error) {
	length := len(errs)
	if length != 0 {
		//若为MaxRetry failed错误，省略重试部份error
		if strings.Contains(errs[length-1].Error(), ErrRetryFailed.Error()) {
			errmsg := fmt.Sprintf("%s %s", errs[length-1], errs[0])
			return errors.New(errmsg)
		}
		//重试后成功了，此时doc != nil. len(errs) != 0
		var errmsg string
		for i := 0; i < length; i++ {
			errmsg = fmt.Sprintf("%s %s", errmsg, errs[i])
		}

		return errors.New(errmsg)
	}

	return nil
}
