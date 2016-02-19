package eden

import (
	"bytes"
	"crypto/tls"
	"fmt"
	jwt "github.com/dgrijalva/jwt-go"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

// Checks the given Authorization header for an encoded
// JWT and verifies it is from a valid sender. Retrieves
// the employee NetId and area Guid and stores in the
// context. Intended to be used as middleware.
func Authorize(c *Context) {

	// Parse JWT from Authorization header
	var tokenString string
	tokenString = c.Request.Header.Get("Authorization")
	if len(tokenString) < 1 {
		c.Fail(401, "No authorization header present")
		return
	}

	// Find the directory with the RSA keys
	dir := os.Getenv("KEYS_DIRECTORY")
	if dir == "" {
		dir = "./keys" // If none given, use the keys directory within the current directory
	}

	// Loop over available public key files
	files, _ := ioutil.ReadDir(dir)
	for _, f := range files {
		name := f.Name()
		// Only look at files with extension .pub
		if name[len(name)-4:] == ".pub" {
			// Once a public is found, decode and try to validate
			// See documentation on the JWT library for how this works
			// The function passed in is a function that looks up the key
			decoded, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				key, err := ioutil.ReadFile(dir + "/" + name) // Read in public key
				if err != nil {
					return nil, err
				}
				return jwt.ParseRSAPublicKeyFromPEM(key)
			})

			// If there was no error in parsing the key and decoding the token
			// and if the token is valid store employee and area guids
			if err == nil && decoded.Valid {
				c.User.NetId = fmt.Sprintf("%v", decoded.Claims["employee"])
				c.User.Area = fmt.Sprintf("%v", decoded.Claims["area"])
				return
			}
		}
	}

	// No public key was able to decode and validate the JWT
	// Send a failed message and abort.
	c.Fail(401, "You are not authorized to make this request")
	return
}

// Sends an authenticated request to the given url with the
// specified http method. Data is a map of data to use as
// post data. Any get data should be put in the url.
func (c *Context) SendAuthenticatedRequest(method, urlStr string, data map[string]string) (*http.Response, error) {
	token := jwt.New(jwt.SigningMethodRS256)

	// Set claims
	token.Claims["exp"] = time.Now().Add(time.Minute * 2).Unix() // Expire in two hours
	token.Claims["nbf"] = time.Now().Unix() - 1                  // Not valid before now - 1 second
	token.Claims["iat"] = time.Now().Unix()                      // Issued at now
	token.Claims["employee"] = c.User.NetId                      // Employee netId
	token.Claims["area"] = c.User.Area                           // Area guid

	// Find private key
	keyFile := os.Getenv("PRIVATE_KEY_FILE")
	if keyFile == "" {
		keyFile = "./keys/key.pem" // if none specified, use key.pem in ./keys directory
	}
	// Parse private key from file
	key, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	pri, err := jwt.ParseRSAPrivateKeyFromPEM(key)
	if err != nil {
		return nil, err
	}

	// Sign the JWT with the private key
	tokenString, err := token.SignedString(pri)
	if err != nil {
		return nil, err
	}

	// Convert the data into a format http Client can use
	postData := url.Values{}
	for k, v := range data {
		postData.Add(k, v)
	}
	// Encode data and add as request body or ignore if empty
	var body io.Reader
	if len(data) > 0 {
		body = bytes.NewBufferString(postData.Encode())
	} else {
		body = nil
	}
	// Form request
	req, err := http.NewRequest(method, urlStr, body)
	if err != nil {
		return nil, err
	}

	// Give the token to the request to make it authorized
	req.Header.Add("Authorization", tokenString)
	// Add other necessary headers
	req.Header.Add("Content-Length", strconv.Itoa(len(postData.Encode())))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Create http client and send request, return response
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr}
	return client.Do(req)
}
