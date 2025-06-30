// subdomain_finder.go
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

type Config struct {
	VT_API_KEY     string
	ST_API_KEY     string
	SHODAN_API_KEY string
	CENSYS_API_ID  string
	CENSYS_SECRET  string
}

func loadEnv() Config {
	return Config{
		VT_API_KEY:     os.Getenv("VT_API_KEY"),
		ST_API_KEY:     os.Getenv("ST_API_KEY"),
		SHODAN_API_KEY: os.Getenv("SHODAN_API_KEY"),
		CENSYS_API_ID:  os.Getenv("CENSYS_API_ID"),
		CENSYS_SECRET:  os.Getenv("CENSYS_SECRET"),
	}
}

func runCommand(command string, args ...string) []string {
	cmd := exec.Command(command, args...)
	output, err := cmd.Output()
	if err != nil {
		return []string{}
	}
	lines := strings.Split(string(output), "\n")
	return lines
}

func fetchCRTsh(domain string) []string {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	resp, err := http.Get(url)
	if err != nil {
		return []string{}
	}
	defer resp.Body.Close()

	var results []map[string]interface{}
	body, _ := ioutil.ReadAll(resp.Body)
	err = json.Unmarshal(body, &results)
	if err != nil {
		return []string{}
	}

	subs := make(map[string]struct{})
	for _, entry := range results {
		name := entry["name_value"].(string)
		parts := strings.Split(name, "\n")
		for _, p := range parts {
			if !strings.Contains(p, "*") {
				subs[strings.TrimSpace(p)] = struct{}{}
			}
		}
	}
	var final []string
	for k := range subs {
		final = append(final, k)
	}
	return final
}

func fetchVirusTotal(domain, key string) []string {
	if key == "" {
		return []string{}
	}
	subs := make(map[string]struct{})
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=100", domain)
	header := http.Header{}
	header.Add("x-apikey", key)

	client := &http.Client{}
	for url != "" {
		req, _ := http.NewRequest("GET", url, nil)
		req.Header = header
		resp, err := client.Do(req)
		if err != nil {
			break
		}
		body, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		var jsonData map[string]interface{}
		json.Unmarshal(body, &jsonData)

		if data, ok := jsonData["data"].([]interface{}); ok {
			for _, d := range data {
				item := d.(map[string]interface{})
				subs[item["id"].(string)] = struct{}{}
			}
		}
		next := ""
		if links, ok := jsonData["links"].(map[string]interface{}); ok {
			if n, ok := links["next"].(string); ok {
				next = n
			}
		}
		url = next
	}
	var final []string
	for k := range subs {
		final = append(final, k)
	}
	return final
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run subdomain_finder.go example.com")
		return
	}
	domain := os.Args[1]
	config := loadEnv()

	fmt.Println("\n🔍 Finding subdomains for:", domain)

	result := make(map[string]bool)

	sources := []struct {
		name string
		fn   func(string) []string
	}{
		{"Assetfinder", func(d string) []string { return runCommand("assetfinder", "--subs-only", d) }},
		{"crt.sh", fetchCRTsh},
		{"Subfinder", func(d string) []string { return runCommand("subfinder", "-d", d, "-silent") }},
		{"Amass", func(d string) []string { return runCommand("amass", "enum", "-passive", "-d", d) }},
		{"VirusTotal", func(d string) []string { return fetchVirusTotal(d, config.VT_API_KEY) }},
	}

	for _, source := range sources {
		fmt.Println("[+] Running:", source.name)
		subs := source.fn(domain)
		for _, s := range subs {
			if s != "" {
				result[s] = true
			}
		}
	}

	fmt.Printf("\n✅ Total Unique Subdomains: %d\n", len(result))
	file, _ := os.Create("subdomains.txt")
	defer file.Close()
	writer := bufio.NewWriter(file)
	for sub := range result {
		fmt.Fprintln(writer, sub)
	}
	writer.Flush()
	fmt.Println("📁 Output saved to: subdomains.txt")
}
