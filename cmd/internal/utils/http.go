package utils

import (
	"bytes"
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

	http.DefaultClient.Timeout = time.Minute * 10
	return http.DefaultClient.Do(req)
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

	http.DefaultClient.Timeout = time.Minute * 10
	return http.DefaultClient.Do(req)
}

func Get(url string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	http.DefaultClient.Timeout = time.Minute * 10
	return http.DefaultClient.Do(req)
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

	http.DefaultClient.Timeout = time.Minute * 10
	return http.DefaultClient.Do(req)
}
