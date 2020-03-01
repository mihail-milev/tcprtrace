package main

import (
  "fmt"
  "container/list"
  "time"
  "os"
  "sync"
  "flag"
  "regexp"
  "strings"
  "errors"
)

const (
  REGEX_FILTER_PARSE_TERM = `(?:^|\s)tcp(?:\s|$)`
)

type ParsedPacket struct {
  SrcPort int
  DstPort int
  SrcAddress string
  DstAddress string
  PacketTime time.Time
  PacketType string
  HashId string
  PacketString string
}

func DisplayErrorAndExit(err string, ecode int) {
  fmt.Println(err)
  os.Exit(ecode)
}

func PrepareFilterString(userinput string) string {
  if userinput == "" {
    return "tcp"
  }
  re := regexp.MustCompile(REGEX_FILTER_PARSE_TERM)
  matches := re.FindAllString(userinput, -1)
  if len(matches) > 0 {
    return userinput
  }
  return "tcp and " + userinput + ""
}

func CheckOutputFile(fpath string) (string, error) {
  if len(fpath) == 0 {
    return "", errors.New("Please specify a destination file using the -o option")
  }
  if fpath[:1] != "/" {
    wd, err := os.Getwd()
    if err != nil {
      return "", err
    }
    fpath = wd + string(os.PathSeparator) + fpath
  }
  pathelements := strings.Split(fpath, string(os.PathSeparator))
  parentdir := strings.Join(pathelements[:len(pathelements)-1], string(os.PathSeparator))
  fmt.Println("Parent dir: " + parentdir)
  _, err := os.Stat(parentdir)
  if err != nil {
    return "", err
  }
  f, err := os.OpenFile(fpath, os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		return "", err
	}
  f.Close()
  return fpath, nil
}

func main() {
  filter := flag.String("f", "", "Specify additional tcpdump filters, default one: \"tcp\"")
  timeout := flag.Float64("t", 2.0, "Duration in seconds after which a still active connection will be dumped to a file, defaults to 2.0")
  interf := flag.String("i", "", "Specify which interface to perform the monitoring on, no default value")
  fpath := flag.String("o", "", "File to write timed-out sessions to")
  flag.Parse()
  if len(*interf) > 0 {
    *interf = "-i " + *interf
  }
  outfilepath, err := CheckOutputFile(*fpath)
  if err != nil {
    DisplayErrorAndExit(fmt.Sprintf("ERROR: %v", err), EXIT_CODE_CANNOT_OPEN_TRUNCATE_FILE)
  }

  msglist := list.New()
  var msglistmutex sync.Mutex

  chainmap := map[string]*list.List{}
  var chainmapmutex sync.Mutex

  newmsgchan := make(chan bool)

  go StartParser(msglist, &msglistmutex, &chainmap, &chainmapmutex, newmsgchan)


  go StartVisualizer(&chainmap, &chainmapmutex, *timeout, outfilepath)

  err = StartTcpDump(newmsgchan, msglist, &msglistmutex, *interf, PrepareFilterString(*filter))
  if err != nil {
    DisplayErrorAndExit(fmt.Sprintf("ERROR: tcpdump command failed with: %v", err), EXIT_CODE_TCPDUMP_FAILED_TO_START)
  }
}
