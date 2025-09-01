package utils

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"time"
)

func Put(url string, values map[string]string, key string) (*http.Response, error) {
	jsonValue, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(jsonValue))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("key", key) // Přidání vlastní hlavičky

	// Vytvoření http.Client s vypnutou kontrolou certifikátu
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Timeout:   time.Minute * 10,
		Transport: tr,
	}
	return client.Do(req)
}

func Post(url string, values map[string]string, headers map[string]string) (*http.Response, error) {
	jsonValue, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	if err != nil {
		return nil, err
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	tr := &http.Transport{}

	client := &http.Client{
		Timeout:   time.Minute * 10,
		Transport: tr,
	}
	return client.Do(req)
}

func Get(url string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Vytvoření http.Client s vypnutou kontrolou certifikátu
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Timeout:   time.Minute * 10,
		Transport: tr,
	}
	return client.Do(req)
}

func Patch(url string, values map[string]string, headers map[string]string) (*http.Response, error) {
	jsonValue, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("PATCH", url, bytes.NewBuffer(jsonValue))
	if err != nil {
		return nil, err
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	tr := &http.Transport{}

	client := &http.Client{
		Timeout:   time.Minute * 10,
		Transport: tr,
	}
	return client.Do(req)
}
