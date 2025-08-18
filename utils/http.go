package utils

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
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

func Post(url string, values map[string]string, key string) (*http.Response, error) {
	jsonValue, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}

	fmt.Println("DEBUG: Sending POST request to", url, "with key:", key)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
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

func Get(url string, key string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

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
