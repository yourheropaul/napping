// Copyright (c) 2012-2013 Jason McVetta.  This is Free Software, released
// under the terms of the GPL v3.  See http://www.gnu.org/copyleft/gpl.html for
// details.  Resist intellectual serfdom - the ownership of ideas is akin to
// slavery.

package napping

/*
This module provides a Session object to manage and persist settings across
requests (cookies, auth, proxies).
*/

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"bitbucket.org/homemade/hmd.io/log"
)

type reg struct {
	reg  *regexp.Regexp
	subs string
}

var concealers = []reg{
	reg{
		reg:  regexp.MustCompile("\"number\":\"\\d+\""),
		subs: `"number:"*******"`,
	},

	reg{
		reg:  regexp.MustCompile("\"cvv2\":\"\\d+\""),
		subs: `"cvv2":"***"`,
	},
	reg{
		reg:  regexp.MustCompile("\"expire_month\":\"\\d+\""),
		subs: `"expire_month":"**"`,
	},
	reg{
		reg:  regexp.MustCompile("\"expire_year\":\"\\d+\""),
		subs: `"expire_year":"**"`,
	},
}

type Session struct {
	Client          *http.Client
	UnsafeBasicAuth bool // Allow Basic Auth over unencrypted HTTP
	Log             bool // Log request and response

	// Optional
	Userinfo *url.Userinfo
	Header   *http.Header
	LogInfo  string
}

// Send constructs and sends an HTTP request.
func (s *Session) Send(r *Request) (response *Response, err error) {
	r.Method = strings.ToUpper(r.Method)
	//
	// Create a URL object from the raw url string.  This will allow us to compose
	// query parameters programmatically and be guaranteed of a well-formed URL.
	//
	u, err := url.Parse(r.Url)
	if err != nil {
		log.Err(err.Error())
		return
	}
	//
	// If the user populated the Params field, then add the params to the URL's
	// querystring.
	//
	if r.Params != nil {
		vals := u.Query()
		for k, v := range *r.Params {
			vals.Set(k, v)
		}
		u.RawQuery = vals.Encode()
	}
	//
	// Create a Request object; if populated, Data field is JSON encoded as
	// request body
	//
	header := http.Header{}
	if s.Header != nil {
		for k, _ := range *s.Header {
			v := s.Header.Get(k)
			header.Set(k, v)
		}
	}
	var req *http.Request
	var payloadStr string
	if r.Payload != nil {
		var b []byte
		b, err = json.Marshal(&r.Payload)
		if err != nil {
			log.Err(err.Error())
			return
		}
		buf := bytes.NewBuffer(b)
		payloadStr = buf.String()
		req, err = http.NewRequest(r.Method, u.String(), buf)
		if err != nil {
			log.Err(err.Error())
			return
		}
		header.Add("Content-Type", "application/json")
	} else { // no data to encode
		req, err = http.NewRequest(r.Method, u.String(), nil)
		if err != nil {
			log.Err(err.Error())
			return
		}

	}
	//
	// Merge Session and Request options
	//
	var userinfo *url.Userinfo
	if s.Userinfo != nil {
		userinfo = s.Userinfo
	}
	// Prefer Request's user credentials
	if r.Userinfo != nil {
		userinfo = r.Userinfo
	}
	if r.Header != nil {
		for k, v := range *r.Header {
			header.Set(k, v[0]) // Is there always guarnateed to be at least one value for a header?
		}
	}
	if header.Get("Accept") == "" {
		header.Add("Accept", "application/json") // Default, can be overridden with Opts
	}
	req.Header = header
	//
	// Set HTTP Basic authentication if userinfo is supplied
	//
	if userinfo != nil {
		if !s.UnsafeBasicAuth && u.Scheme != "https" {
			err = errors.New("Unsafe to use HTTP Basic authentication without HTTPS")
			return
		}
		pwd, _ := userinfo.Password()
		req.SetBasicAuth(userinfo.Username(), pwd)
	}
	//
	// Execute the HTTP request
	//
	if s.Log {
		log.Info(s.LogInfo + "--------------------------------------------------------------------------------")
		log.Info(s.LogInfo + "REQUEST")
		log.Info(s.LogInfo + "--------------------------------------------------------------------------------")
		log.Info(s.LogInfo + fmt.Sprintf("%v", req))
		log.Info(s.LogInfo + "Payload: ")
		for _, r := range concealers {
			payloadStr = r.reg.ReplaceAllString(payloadStr, r.subs)
		}

		log.Info(s.LogInfo + payloadStr)
	}
	r.timestamp = time.Now()
	var client *http.Client
	if s.Client != nil {
		client = s.Client
	} else {
		client = &http.Client{}
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Err(err.Error())
		return
	}
	defer resp.Body.Close()
	r.status = resp.StatusCode
	r.response = resp
	//
	// Unmarshal
	//
	r.body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Err(err.Error())
		return
	}
	if string(r.body) != "" {
		if resp.StatusCode < 300 && r.Result != nil {
			err = json.Unmarshal(r.body, r.Result)
		}
		if resp.StatusCode >= 400 && r.Error != nil {
			json.Unmarshal(r.body, r.Error) // Should we ignore unmarshall error?
		}
	}
	rsp := Response(*r)
	response = &rsp
	if s.Log {
		log.Info(s.LogInfo + "--------------------------------------------------------------------------------")
		log.Info(s.LogInfo + "RESPONSE")
		log.Info(s.LogInfo + "--------------------------------------------------------------------------------")
		log.Info(s.LogInfo+"Status: %v", response.status)
		log.Info(s.LogInfo+"Header: %+v", response.HttpResponse().Header)
		log.Info("Body:")
		if response.body != nil {
			raw := json.RawMessage{}
			if json.Unmarshal(response.body, &raw) == nil {
				log.Info(s.LogInfo + string(raw))
			} else {
				log.Info(s.LogInfo + string(response.RawText()))
			}
		} else {
			log.Info(s.LogInfo + "Empty response body")
		}

	}
	return
}

// Get sends a GET request.
func (s *Session) Get(url string, p *Params, result, errMsg interface{}) (*Response, error) {
	r := Request{
		Method: "GET",
		Url:    url,
		Params: p,
		Result: result,
		Error:  errMsg,
	}
	return s.Send(&r)
}

// Options sends an OPTIONS request.
func (s *Session) Options(url string, result, errMsg interface{}) (*Response, error) {
	r := Request{
		Method: "OPTIONS",
		Url:    url,
		Result: result,
		Error:  errMsg,
	}
	return s.Send(&r)
}

// Head sends a HEAD request.
func (s *Session) Head(url string, result, errMsg interface{}) (*Response, error) {
	r := Request{
		Method: "HEAD",
		Url:    url,
		Result: result,
		Error:  errMsg,
	}
	return s.Send(&r)
}

// Post sends a POST request.
func (s *Session) Post(url string, payload, result, errMsg interface{}) (*Response, error) {
	r := Request{
		Method:  "POST",
		Url:     url,
		Payload: payload,
		Result:  result,
		Error:   errMsg,
	}
	return s.Send(&r)
}

// Put sends a PUT request.
func (s *Session) Put(url string, payload, result, errMsg interface{}) (*Response, error) {
	r := Request{
		Method:  "PUT",
		Url:     url,
		Payload: payload,
		Result:  result,
		Error:   errMsg,
	}
	return s.Send(&r)
}

// Patch sends a PATCH request.
func (s *Session) Patch(url string, payload, result, errMsg interface{}) (*Response, error) {
	r := Request{
		Method:  "PATCH",
		Url:     url,
		Payload: payload,
		Result:  result,
		Error:   errMsg,
	}
	return s.Send(&r)
}

// Delete sends a DELETE request.
func (s *Session) Delete(url string, result, errMsg interface{}) (*Response, error) {
	r := Request{
		Method: "DELETE",
		Url:    url,
		Result: result,
		Error:  errMsg,
	}
	return s.Send(&r)
}
