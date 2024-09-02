package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

type LoginInfo struct {
	SourceIP string
	SourcePort string
	Username string
	Counter int
}

const (
	SSH_SERVICE = "sshd"
	PASSWORD_FAILURE = "Failed password"
	THRESHOLD = 10
)

func parseLog(log string) LoginInfo {
	val := LoginInfo{}
	str := string(log)
	if strings.Contains(str, SSH_SERVICE) && strings.Contains(str, PASSWORD_FAILURE) {
		a := strings.Split(str, "for")
		if len(a) < 2 {
			fmt.Println("ERROR: could not understand log format")
			os.Exit(-1)
		}

		info := strings.Split(a[1], " ")
		if len(info) < 6 {
			fmt.Println("Length is not enough")
			return val
		}
		val.SourceIP = info[3]
		val.Username = info[1]
		val.SourcePort = info[5]
	}

	return val
}

func detection(filename string) {
	loginFailure := map[string]LoginInfo{}
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println("ERROR: could not open the file", err)
		os.Exit(-1)
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadString('\n')
		info := parseLog(line)
		if value, ok := loginFailure[info.SourceIP]; ok {
			value.Counter++
			loginFailure[info.SourceIP] = value
		} else {
			loginFailure[info.SourceIP] = info
		}
		if err == io.EOF {
			break
		}
	}

	for ip, failure := range loginFailure {
		if ip != "" && failure.Counter >= THRESHOLD {
			fmt.Printf("Possible brute force detection from IP %s with %d login tries\n", ip, failure.Counter)
			return
		} else if ip != "" && failure.Counter < THRESHOLD {
			fmt.Printf("Not reaching the treshold, but could be a possible brute force attempt with total login tries %d\n", failure.Counter)
		}
	}
}

func main() {
	// if len(os.Args) < 2 {
	// 	fmt.Println("ERROR: please provide log file path as argument")
	// 	return
	// }
	// println(os.Args)
	detection("ssh_bruteforce.log")
}